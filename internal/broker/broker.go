package broker

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/secretharbor/secretharbor/internal/audit"
)

// DefaultCapabilityTTL is the non-zero default validity duration for registered capabilities (BUG-040).
const DefaultCapabilityTTL = 1 * time.Hour

// Capability defines an authorized egress substitution rule for a secret.
type Capability struct {
	SecretName   string    `json:"secret_name"`
	FakeToken    string    `json:"fake_token"`
	RealSecret   string    `json:"-"` // Never serialized
	AllowedHosts []string  `json:"allowed_hosts"`
	Enabled      bool      `json:"enabled"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Broker coordinates runtime secret injection on authorized outbound connections.
type Broker struct {
	mu           sync.RWMutex
	capabilities map[string]*Capability // FakeToken -> Capability
}

// GlobalBroker is the active secret broker instance.
var GlobalBroker = NewBroker()

// NewBroker initializes an empty secret broker.
func NewBroker() *Broker {
	return &Broker{
		capabilities: make(map[string]*Capability),
	}
}

// Register registers a new capability mapping a fake token to a real credential for specific hosts.
// Supports a non-zero default TTL when ttl is 0 (BUG-040).
func (b *Broker) Register(secretName, fakeToken, realSecret string, allowedHosts []string, ttl time.Duration) {
	if fakeToken == "" || realSecret == "" {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if ttl == 0 {
		ttl = DefaultCapabilityTTL
	}
	expiresAt := time.Now().Add(ttl)

	var lowerHosts []string
	for _, h := range allowedHosts {
		lowerHosts = append(lowerHosts, extractTargetHost(h))
	}

	b.capabilities[fakeToken] = &Capability{
		SecretName:   secretName,
		FakeToken:    fakeToken,
		RealSecret:   realSecret,
		AllowedHosts: lowerHosts,
		Enabled:      true,
		ExpiresAt:    expiresAt,
	}
}

// HasCapabilityForHost returns true if any registered capability permits injection for the target host.
// Parses host and port using net.SplitHostPort supporting IPv6 (BUG-040).
func (b *Broker) HasCapabilityForHost(host string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	host = extractTargetHost(host)

	now := time.Now()
	for _, cap := range b.capabilities {
		if !cap.Enabled {
			continue
		}
		if !cap.ExpiresAt.IsZero() && now.After(cap.ExpiresAt) {
			continue
		}
		if isHostApproved(host, cap.AllowedHosts) {
			return true
		}
	}
	return false
}

// InterceptAndInject inspects an outbound HTTP request, checks if the destination host is authorized,
// and transparently substitutes fake tokens with real credentials.
func (b *Broker) InterceptAndInject(req *http.Request) bool {
	if req == nil {
		return false
	}

	rawHost := req.Host
	if rawHost == "" && req.URL != nil {
		rawHost = req.URL.Host
	}
	targetHost := extractTargetHost(rawHost)

	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now()
	injected := false

	for fakeToken, cap := range b.capabilities {
		if !cap.Enabled {
			continue
		}
		if !cap.ExpiresAt.IsZero() && now.After(cap.ExpiresAt) {
			continue
		}

		// Verify target host is explicitly approved for this secret capability
		if !isHostApproved(targetHost, cap.AllowedHosts) {
			continue
		}

		// 1. Substitute in Authorization headers
		for headerName, values := range req.Header {
			for i, val := range values {
				if strings.Contains(val, fakeToken) {
					req.Header[headerName][i] = strings.ReplaceAll(val, fakeToken, cap.RealSecret)
					injected = true
					audit.GlobalLogger.Log("broker", "inject_header", cap.SecretName, "allowed", fmt.Sprintf("host: %s", targetHost))
				}
			}
		}

		// 2. Substitute in URL query parameters if present
		if req.URL != nil && strings.Contains(req.URL.RawQuery, fakeToken) {
			req.URL.RawQuery = strings.ReplaceAll(req.URL.RawQuery, fakeToken, cap.RealSecret)
			injected = true
			audit.GlobalLogger.Log("broker", "inject_query", cap.SecretName, "allowed", fmt.Sprintf("host: %s", targetHost))
		}

		// 3. Substitute in request body and restore body on read failure or when injection not needed (BUG-040)
		if req.Body != nil && req.Body != http.NoBody {
			bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, 1048576))
			if err != nil {
				// Restore body on read failure
				if len(bodyBytes) > 0 {
					req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				}
			} else if len(bodyBytes) > 0 {
				if bytes.Contains(bodyBytes, []byte(fakeToken)) {
					newBody := bytes.ReplaceAll(bodyBytes, []byte(fakeToken), []byte(cap.RealSecret))
					req.Body = io.NopCloser(bytes.NewReader(newBody))
					req.ContentLength = int64(len(newBody))
					injected = true
					audit.GlobalLogger.Log("broker", "inject_body", cap.SecretName, "allowed", fmt.Sprintf("host: %s", targetHost))
				} else {
					// Restore request body when injection not needed
					req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				}
			}
		}
	}

	return injected
}

func extractTargetHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if h, _, err := net.SplitHostPort(raw); err == nil {
		raw = h
	}
	// Strip IPv6 square brackets if present (e.g. [::1] -> ::1)
	raw = strings.TrimPrefix(strings.TrimSuffix(raw, "]"), "[")
	return strings.ToLower(raw)
}

func isHostApproved(targetHost string, allowedHosts []string) bool {
	targetHost = extractTargetHost(targetHost)
	for _, h := range allowedHosts {
		cleanH := extractTargetHost(h)
		if targetHost == cleanH || strings.HasSuffix(targetHost, "."+cleanH) {
			return true
		}
	}
	return false
}
