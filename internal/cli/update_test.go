package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/secretharbor/secretharbor/internal/updater"
)

type cliMockRoundTripper struct {
	handler http.Handler
}

func (m *cliMockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	m.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

func TestCliUpdateCheckAndDryRun(t *testing.T) {
	platformKey := updater.GetPlatformKey()
	mockPayload := []byte("new-version-binary")
	hasher := sha256.New()
	hasher.Write(mockPayload)
	mockHash := hex.EncodeToString(hasher.Sum(nil))

	mockManifest := updater.ReleaseManifest{
		Version:     "0.5.0",
		PublishedAt: time.Now(),
		Artifacts: map[string]updater.ArtifactInfo{
			platformKey: {
				URL:      "http://secretharbor.test/download/shb",
				Filename: "shb-" + platformKey,
				SHA256:   mockHash,
				Size:     int64(len(mockPayload)),
			},
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mockManifest)
	})
	mux.HandleFunc("/download/shb", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mockPayload)
	})

	origTransport := updater.HTTPClient.Transport
	defer func() { updater.HTTPClient.Transport = origTransport }()
	updater.HTTPClient.Transport = &cliMockRoundTripper{handler: mux}

	origURL := os.Getenv("SECRETHARBOR_UPDATE_URL")
	defer func() { _ = os.Setenv("SECRETHARBOR_UPDATE_URL", origURL) }()
	_ = os.Setenv("SECRETHARBOR_UPDATE_URL", "http://secretharbor.test")

	// 1. Test shb update --check (human)
	outCheck := captureStdout(func() {
		if err := RunUpdate("shb", []string{"--check"}); err != nil {
			t.Errorf("shb update --check failed: %v", err)
		}
	})
	if !strings.Contains(outCheck, "Latest version: 0.5.0") {
		t.Errorf("expected Latest version: 0.5.0, got: %s", outCheck)
	}
	if !strings.Contains(outCheck, "Update available.") {
		t.Errorf("expected Update available, got: %s", outCheck)
	}

	// 2. Test shb update --check --json
	outCheckJSON := captureStdout(func() {
		if err := RunUpdate("shb", []string{"--check", "--json"}); err != nil {
			t.Errorf("shb update --check --json failed: %v", err)
		}
	})
	var checkRes updater.UpdateCheckResult
	if err := json.Unmarshal([]byte(outCheckJSON), &checkRes); err != nil {
		t.Fatalf("failed to parse json update check: %v, raw: %s", err, outCheckJSON)
	}
	if checkRes.LatestVersion != "0.5.0" || !checkRes.UpdateAvailable {
		t.Errorf("unexpected check json: %+v", checkRes)
	}

	// 3. Test shb update --dry-run
	outDryRun := captureStdout(func() {
		if err := RunUpdate("shb", []string{"--dry-run"}); err != nil {
			t.Errorf("shb update --dry-run failed: %v", err)
		}
	})
	if !strings.Contains(outDryRun, "SecretHarbor update simulation successful.") {
		t.Errorf("expected simulation success, got: %s", outDryRun)
	}
	if !strings.Contains(outDryRun, "0.5.0") {
		t.Errorf("expected target version 0.5.0 in dry run, got: %s", outDryRun)
	}

	// 4. Test shb update Agent Lockout
	origEnv := os.Getenv("SECRETHARBOR_SANDBOX")
	defer func() { _ = os.Setenv("SECRETHARBOR_SANDBOX", origEnv) }()
	_ = os.Setenv("SECRETHARBOR_SANDBOX", "1")

	err := RunUpdate("shb", []string{"--check"})
	if err == nil {
		t.Errorf("expected agent lockout error for update, got nil")
	} else if !strings.Contains(err.Error(), "Permission denied: SecretHarbor self-update is human-controlled") {
		t.Errorf("expected agent lockout error, got: %v", err)
	}
}
