package updater

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// DefaultReleaseBaseURL is the official distribution endpoint for SecretHarbor releases.
// GitHub Releases is the canonical source; set SECRETHARBOR_UPDATE_URL to use a mirror.
const DefaultReleaseBaseURL = "https://github.com/logn10/SecretHarbor/releases"

// DefaultGitHubRepo is the canonical GitHub repository for release lookups.
const DefaultGitHubRepo = "logn10/SecretHarbor"

// ArtifactInfo details a platform-specific binary or archive release artifact.
type ArtifactInfo struct {
	URL      string `json:"url"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// ReleaseManifest contains metadata about available SecretHarbor releases.
type ReleaseManifest struct {
	Version      string                  `json:"version"`
	PublishedAt  time.Time               `json:"published_at"`
	ReleaseNotes string                  `json:"release_notes,omitempty"`
	Artifacts    map[string]ArtifactInfo `json:"artifacts"` // key: "darwin-arm64", "linux-amd64", etc.
	Signatures   map[string]string       `json:"signatures,omitempty"`
}

// GetPlatformKey returns the platform key formatted as "os-arch" (e.g. "darwin-arm64", "linux-amd64").
func GetPlatformKey() string {
	return fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH)
}

// HTTPClient is the HTTP client used for fetching manifests and release artifacts.
var HTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

// ValidateHTTPSURL ensures that distribution and artifact URLs use HTTPS,
// with exceptions allowed only for local test domains.
func ValidateHTTPSURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	host := u.Hostname()
	if strings.HasSuffix(host, ".test") || host == "localhost" || host == "127.0.0.1" || strings.HasPrefix(host, "127.") {
		return nil
	}
	if strings.ToLower(u.Scheme) != "https" {
		return fmt.Errorf("insecure URL rejected (%s): SecretHarbor requires HTTPS for release updates", rawURL)
	}
	return nil
}

func formatNetworkError(endpoint string, err error) error {
	if err == nil {
		return nil
	}
	errStr := err.Error()
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "lookup") {
		return fmt.Errorf("unable to reach update server at %s: DNS resolution failed (no such host). Please verify your internet connection or check proxy settings", endpoint)
	}
	if strings.Contains(errStr, "connection refused") {
		return fmt.Errorf("unable to reach update server at %s: connection refused", endpoint)
	}
	if strings.Contains(errStr, "i/o timeout") || strings.Contains(errStr, "Client.Timeout") {
		return fmt.Errorf("unable to reach update server at %s: connection timed out", endpoint)
	}
	return fmt.Errorf("network error contacting update server at %s: %w", endpoint, err)
}

// releaseManifestURL builds the manifest location for GitHub Releases or a self-hosted mirror.
func releaseManifestURL(baseURL, targetVersion string) string {
	trimmed := strings.TrimRight(baseURL, "/")
	version := strings.TrimPrefix(targetVersion, "v")

	if strings.HasPrefix(trimmed, "https://github.com/") && strings.HasSuffix(trimmed, "/releases") {
		if version == "" {
			return trimmed + "/latest/download/manifest.json"
		}
		return fmt.Sprintf("%s/download/v%s/manifest.json", trimmed, version)
	}

	if version == "" {
		return trimmed + "/manifest.json"
	}
	return fmt.Sprintf("%s/v%s/manifest.json", trimmed, version)
}

// FetchReleaseManifest downloads and decodes the release manifest from the release server.
func FetchReleaseManifest(customURL string) (*ReleaseManifest, error) {
	return FetchReleaseManifestForVersion(customURL, "")
}

// FetchReleaseManifestForVersion downloads release manifest metadata for a target version or latest.
func FetchReleaseManifestForVersion(customURL string, targetVersion string) (*ReleaseManifest, error) {
	baseURL := os.Getenv("SECRETHARBOR_UPDATE_URL")
	if baseURL == "" {
		baseURL = customURL
	}
	if baseURL == "" {
		baseURL = DefaultReleaseBaseURL
	}

	if err := ValidateHTTPSURL(baseURL); err != nil {
		return nil, err
	}

	manifestURL := releaseManifestURL(baseURL, targetVersion)
	client := HTTPClient

	req, err := http.NewRequest(http.MethodGet, manifestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create manifest request: %w", err)
	}
	req.Header.Set("User-Agent", fmt.Sprintf("SecretHarbor-Updater/%s (%s; %s)", "0.1.0", runtime.GOOS, runtime.GOARCH))

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		var firstErr error
		if err != nil {
			firstErr = formatNetworkError(manifestURL, err)
		} else {
			_ = resp.Body.Close()
			firstErr = fmt.Errorf("release manifest request failed (HTTP %d)", resp.StatusCode)
		}

		// Fallback to GitHub Releases API if central CDN is unreachable or returns error
		ghManifest, ghErr := fetchGitHubReleaseManifest(targetVersion)
		if ghErr == nil && ghManifest != nil {
			return ghManifest, nil
		}

		if firstErr != nil {
			return nil, firstErr
		}
		if ghErr != nil {
			return nil, ghErr
		}
		return nil, fmt.Errorf("failed to fetch release manifest from %s", manifestURL)
	}
	defer resp.Body.Close()

	var manifest ReleaseManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("failed to parse release manifest: %w", err)
	}

	return &manifest, nil
}

type gitHubReleaseResponse struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	PublishedAt string `json:"published_at"`
	Body        string `json:"body"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}

func fetchGitHubReleaseManifest(targetVersion string) (*ReleaseManifest, error) {
	ghURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", DefaultGitHubRepo)
	if targetVersion != "" {
		ghURL = fmt.Sprintf("https://api.github.com/repos/%s/releases/tags/v%s", DefaultGitHubRepo, strings.TrimPrefix(targetVersion, "v"))
	}

	req, err := http.NewRequest(http.MethodGet, ghURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SecretHarbor-Updater/0.1.0")
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, formatNetworkError(ghURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var ghResp gitHubReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&ghResp); err != nil {
		return nil, err
	}

	version := strings.TrimPrefix(ghResp.TagName, "v")
	manifest := &ReleaseManifest{
		Version:      version,
		ReleaseNotes: ghResp.Body,
		Artifacts:    make(map[string]ArtifactInfo),
	}
	if parsedTime, err := time.Parse(time.RFC3339, ghResp.PublishedAt); err == nil {
		manifest.PublishedAt = parsedTime
	}

	// Attach published SHA-256 hashes from the release checksums.txt asset so the
	// API fallback is still cryptographically verifiable.
	hashes := make(map[string]string)
	for _, asset := range ghResp.Assets {
		if asset.Name == "checksums.txt" {
			if parsed, err := fetchChecksums(asset.BrowserDownloadURL); err == nil {
				hashes = parsed
			}
			break
		}
	}

	for _, asset := range ghResp.Assets {
		for _, osName := range []string{"darwin", "linux", "windows"} {
			for _, arch := range []string{"arm64", "amd64"} {
				key := fmt.Sprintf("%s-%s", osName, arch)
				if strings.Contains(asset.Name, osName) && strings.Contains(asset.Name, arch) {
					manifest.Artifacts[key] = ArtifactInfo{
						URL:      asset.BrowserDownloadURL,
						Filename: asset.Name,
						SHA256:   hashes[asset.Name],
						Size:     asset.Size,
					}
				}
			}
		}
	}

	return manifest, nil
}

// fetchChecksums downloads a goreleaser checksums.txt file into filename -> sha256.
func fetchChecksums(rawURL string) (map[string]string, error) {
	resp, err := HTTPClient.Get(rawURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksums request failed (HTTP %d)", resp.StatusCode)
	}

	out := make(map[string]string)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 2 {
			out[fields[1]] = fields[0]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// CompareVersions compares two SemVer strings (e.g. "0.4.0-prod" vs "0.4.0").
// Precedence follows SemVer 2.0.0 rules:
// - Major, minor, and patch are compared numerically.
// - Normal release has higher precedence than prerelease (0.4.0 > 0.4.0-prod).
// - Prereleases are compared identifier by identifier (numeric vs non-numeric).
// - Build metadata (+...) is ignored.
// Returns 1 if v1 > v2, -1 if v1 < v2, and 0 if v1 == v2.
func CompareVersions(v1, v2 string) int {
	clean1, pre1 := splitSemver(v1)
	clean2, pre2 := splitSemver(v2)

	// 1. Compare numeric core parts (MAJOR.MINOR.PATCH)
	parts1 := strings.Split(clean1, ".")
	parts2 := strings.Split(clean2, ".")
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		num1 := 0
		num2 := 0
		if i < len(parts1) {
			num1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			num2, _ = strconv.Atoi(parts2[i])
		}
		if num1 > num2 {
			return 1
		}
		if num1 < num2 {
			return -1
		}
	}

	// 2. Core parts are identical. Check prerelease precedence.
	// Normal version has higher precedence than prerelease (SemVer 2.0.0 §11.4).
	if pre1 == "" && pre2 != "" {
		return 1
	}
	if pre1 != "" && pre2 == "" {
		return -1
	}
	if pre1 == "" && pre2 == "" {
		return 0
	}

	// Both have prereleases: compare identifier by identifier
	return comparePrereleases(pre1, pre2)
}

func splitSemver(v string) (string, string) {
	v = strings.TrimSpace(strings.TrimPrefix(v, "v"))
	// Strip build metadata
	if idx := strings.Index(v, "+"); idx != -1 {
		v = v[:idx]
	}
	// Separate prerelease
	if idx := strings.Index(v, "-"); idx != -1 {
		return v[:idx], v[idx+1:]
	}
	return v, ""
}

func comparePrereleases(pre1, pre2 string) int {
	ids1 := strings.Split(pre1, ".")
	ids2 := strings.Split(pre2, ".")

	minLen := len(ids1)
	if len(ids2) < minLen {
		minLen = len(ids2)
	}

	for i := 0; i < minLen; i++ {
		id1 := ids1[i]
		id2 := ids2[i]

		num1, err1 := strconv.Atoi(id1)
		num2, err2 := strconv.Atoi(id2)

		if err1 == nil && err2 == nil {
			// Both are numeric: compare numerically
			if num1 > num2 {
				return 1
			}
			if num1 < num2 {
				return -1
			}
		} else if err1 == nil && err2 != nil {
			// Numeric identifier has lower precedence than non-numeric
			return -1
		} else if err1 != nil && err2 == nil {
			// Non-numeric has higher precedence than numeric
			return 1
		} else {
			// Both non-numeric: compare ASCII order
			if id1 > id2 {
				return 1
			}
			if id1 < id2 {
				return -1
			}
		}
	}

	// All shared identifiers equal: larger set of identifiers has higher precedence
	if len(ids1) > len(ids2) {
		return 1
	}
	if len(ids1) < len(ids2) {
		return -1
	}

	return 0
}
