package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		v1       string
		v2       string
		expected int
	}{
		{"0.2.0", "0.2.0", 0},
		{"v0.2.0", "0.2.0", 0},
		{"0.2.0-prod", "0.2.0", -1}, // Normal version has higher precedence than prerelease
		{"0.2.0", "0.2.0-prod", 1},
		{"0.4.0-prod", "0.4.0-prod", 0},
		{"0.4.0-alpha", "0.4.0-beta", -1},
		{"0.4.0-beta.1", "0.4.0-beta.2", -1},
		{"0.4.0-beta.2", "0.4.0-beta.10", -1},
		{"0.3.0", "0.2.0", 1},
		{"0.2.0", "0.3.0", -1},
		{"1.0.0", "0.9.9", 1},
		{"0.1.9", "0.2.0", -1},
		{"0.4.0+build1", "0.4.0+build2", 0}, // Build metadata ignored
	}

	for _, tc := range tests {
		res := CompareVersions(tc.v1, tc.v2)
		if res != tc.expected {
			t.Errorf("CompareVersions(%q, %q) = %d, expected %d", tc.v1, tc.v2, res, tc.expected)
		}
	}
}

func TestVerifyBytesSHA256(t *testing.T) {
	data := []byte("hello world secret harbor")
	hasher := sha256.New()
	hasher.Write(data)
	expectedHex := hex.EncodeToString(hasher.Sum(nil))

	if err := VerifyBytesSHA256(data, expectedHex); err != nil {
		t.Errorf("expected valid sha256 check, got: %v", err)
	}

	if err := VerifyBytesSHA256(data, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Errorf("expected error on hash mismatch, got nil")
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 keypair: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	data := []byte("secret-harbor-release-binary-bytes")
	sig := ed25519.Sign(priv, data)
	sigHex := hex.EncodeToString(sig)

	// Valid signature
	if err := VerifySignature(data, sigHex, pubHex); err != nil {
		t.Errorf("expected valid signature verification, got: %v", err)
	}

	// Tampered data
	tampered := []byte("tampered-release-binary-bytes")
	if err := VerifySignature(tampered, sigHex, pubHex); err == nil {
		t.Errorf("expected error on tampered data, got nil")
	}

	// Empty signature
	if err := VerifySignature(data, "", pubHex); err == nil {
		t.Errorf("expected error for empty signature, got nil")
	}

	// Corrupt signature
	corruptSig := sigHex[:len(sigHex)-4] + "0000"
	if err := VerifySignature(data, corruptSig, pubHex); err == nil {
		t.Errorf("expected error for corrupt signature, got nil")
	}
}

func TestAgentLockout(t *testing.T) {
	orig := os.Getenv("SECRETHARBOR_SANDBOX")
	defer func() { _ = os.Setenv("SECRETHARBOR_SANDBOX", orig) }()

	_ = os.Setenv("SECRETHARBOR_SANDBOX", "1")
	err := CheckAgentLockout()
	if err == nil {
		t.Errorf("expected agent lockout error, got nil")
	} else if !strings.Contains(err.Error(), "Permission denied: SecretHarbor self-update is human-controlled") {
		t.Errorf("unexpected error message: %v", err)
	}

	_ = os.Setenv("SECRETHARBOR_SANDBOX", "")
	if err := CheckAgentLockout(); err != nil {
		t.Errorf("expected no lockout outside sandbox, got: %v", err)
	}
}

func TestFetchManifestAndCheckUpdate(t *testing.T) {
	platformKey := GetPlatformKey()
	mockPayload := []byte("mock binary content")
	hasher := sha256.New()
	hasher.Write(mockPayload)
	mockHash := hex.EncodeToString(hasher.Sum(nil))

	mockManifest := ReleaseManifest{
		Version:     "0.5.0",
		PublishedAt: time.Now(),
		Artifacts: map[string]ArtifactInfo{
			platformKey: {
				URL:      "",
				Filename: "shb-" + platformKey,
				SHA256:   mockHash,
				Size:     int64(len(mockPayload)),
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		mockManifest.Artifacts[platformKey] = ArtifactInfo{
			URL:      "http://secretharbor.test/download/shb",
			Filename: "shb-" + platformKey,
			SHA256:   mockHash,
			Size:     int64(len(mockPayload)),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockManifest)
	})
	mux.HandleFunc("/download/shb", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mockPayload)
	})

	origTransport := HTTPClient.Transport
	defer func() { HTTPClient.Transport = origTransport }()
	HTTPClient.Transport = &inMemoryRoundTripper{handler: mux}

	origURL := os.Getenv("SECRETHARBOR_UPDATE_URL")
	defer func() { _ = os.Setenv("SECRETHARBOR_UPDATE_URL", origURL) }()
	_ = os.Setenv("SECRETHARBOR_UPDATE_URL", "http://secretharbor.test")

	// Check update from older version
	check, err := CheckForUpdate("0.4.2", "")
	if err != nil {
		t.Fatalf("CheckForUpdate failed: %v", err)
	}
	if !check.UpdateAvailable {
		t.Errorf("expected update available from 0.4.2 to 0.5.0")
	}
	if check.LatestVersion != "0.5.0" {
		t.Errorf("expected latest version 0.5.0, got %s", check.LatestVersion)
	}

	// Check update from same version
	checkSame, err := CheckForUpdate("0.5.0", "")
	if err != nil {
		t.Fatalf("CheckForUpdate failed: %v", err)
	}
	if checkSame.UpdateAvailable {
		t.Errorf("expected no update available when already at 0.5.0")
	}

	// Test downgrade prevention when requestedVersion is empty
	checkNewer, err := CheckForUpdate("0.6.0", "")
	if err != nil {
		t.Fatalf("CheckForUpdate failed: %v", err)
	}
	if checkNewer.UpdateAvailable {
		t.Errorf("expected update not available when running version 0.6.0 > 0.5.0 (downgrade prevention)")
	}

	// Test dry-run update
	res, err := ApplyUpdate("0.4.2", "", true)
	if err != nil {
		t.Fatalf("ApplyUpdate dry-run failed: %v", err)
	}
	if !res.DryRun || !res.Success {
		t.Errorf("expected dry run success, got %+v", res)
	}
}

func TestAtomicFileRollback(t *testing.T) {
	tmpDir := t.TempDir()
	origBin := filepath.Join(tmpDir, "dummy_bin")
	_ = os.WriteFile(origBin, []byte("version 1"), 0755)

	backupBin := origBin + ".old"
	_ = os.Rename(origBin, backupBin)

	if err := os.Rename(backupBin, origBin); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	content, err := os.ReadFile(origBin)
	if err != nil || string(content) != "version 1" {
		t.Errorf("unexpected content after rollback: %s", string(content))
	}
}

func TestFetchManifestGitHubFallback(t *testing.T) {
	platformKey := GetPlatformKey()
	mockGHResp := gitHubReleaseResponse{
		TagName:     "v0.9.0",
		Name:        "Release v0.9.0",
		PublishedAt: time.Now().Format(time.RFC3339),
		Body:        "Fallback release notes",
		Assets: []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
			Size               int64  `json:"size"`
		}{
			{
				Name:               "secretharbor_" + platformKey + ".tar.gz",
				BrowserDownloadURL: "https://github.com/logn10/SecretHarbor/releases/download/v0.9.0/asset.tar.gz",
				Size:               1234567,
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not found on CDN", http.StatusNotFound)
	})
	mux.HandleFunc("/repos/logn10/SecretHarbor/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockGHResp)
	})

	origTransport := HTTPClient.Transport
	defer func() { HTTPClient.Transport = origTransport }()
	HTTPClient.Transport = &inMemoryRoundTripper{handler: mux}

	origURL := os.Getenv("SECRETHARBOR_UPDATE_URL")
	defer func() { _ = os.Setenv("SECRETHARBOR_UPDATE_URL", origURL) }()
	_ = os.Setenv("SECRETHARBOR_UPDATE_URL", "http://secretharbor.test")

	manifest, err := FetchReleaseManifest("")
	if err != nil {
		t.Fatalf("expected successful fallback to GitHub releases, got error: %v", err)
	}
	if manifest.Version != "0.9.0" {
		t.Errorf("expected version 0.9.0 from GitHub fallback, got %s", manifest.Version)
	}
	if _, ok := manifest.Artifacts[platformKey]; !ok {
		t.Errorf("expected artifact for %s in manifest from GitHub fallback", platformKey)
	}
}

func TestZipSlipProtection(t *testing.T) {
	// Create tar.gz with malicious path traversal "../../../bin/evil"
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	header := &tar.Header{
		Name: "../../../bin/shb",
		Mode: 0755,
		Size: int64(len("malicious")),
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("failed to write tar header: %v", err)
	}
	if _, err := tw.Write([]byte("malicious")); err != nil {
		t.Fatalf("failed to write tar body: %v", err)
	}
	_ = tw.Close()
	_ = gw.Close()

	_, err := extractExecutableBytes(buf.Bytes(), "malicious.tar.gz")
	if err == nil {
		t.Fatalf("expected zip-slip path traversal error, got nil")
	}
	if !strings.Contains(err.Error(), "zip-slip") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestHTTPSValidation(t *testing.T) {
	if err := ValidateHTTPSURL("http://insecure-cdn.example.com/asset.tar.gz"); err == nil {
		t.Errorf("expected error for non-HTTPS URL, got nil")
	}
	if err := ValidateHTTPSURL("https://releases.secretharbor.dev/asset.tar.gz"); err != nil {
		t.Errorf("expected valid HTTPS URL, got: %v", err)
	}
	// Test domains allowed
	if err := ValidateHTTPSURL("http://localhost:8080/asset.tar.gz"); err != nil {
		t.Errorf("expected localhost allowed, got: %v", err)
	}
}

func TestNetworkErrorFormatting(t *testing.T) {
	dnsErr := fmt.Errorf("dial tcp: lookup nonexistent.secretharbor.dev: no such host")
	formatted := formatNetworkError("https://nonexistent.secretharbor.dev/manifest.json", dnsErr)
	if !strings.Contains(formatted.Error(), "DNS resolution failed") {
		t.Errorf("expected formatted DNS error message, got: %v", formatted)
	}
}

type inMemoryRoundTripper struct {
	handler http.Handler
}

func (m *inMemoryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	m.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}
