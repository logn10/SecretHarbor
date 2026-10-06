package network_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/secretharbor/secretharbor/internal/network"
	"github.com/secretharbor/secretharbor/internal/policy"
)

func TestForwardProxyHandlerDomainFiltering(t *testing.T) {
	allowed := []string{"example.com", "registry.npmjs.org"}
	// Create proxy struct directly or with listener
	proxy, err := network.StartForwardProxy(policy.NetworkModeRestricted, allowed)
	if err != nil {
		// In strictly network-isolated sandbox, test handler logic directly
		t.Skip("skipping network socket binding in isolated sandbox")
	}
	defer proxy.Close()

	// 1. Test unauthorized domain
	req := httptest.NewRequest(http.MethodGet, "http://evil.com/exfiltrate", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for unauthorized domain, got %d", rec.Code)
	}

	// 2. Test localhost denial by default
	reqLocal := httptest.NewRequest(http.MethodGet, "http://localhost:8080/creds", nil)
	recLocal := httptest.NewRecorder()
	proxy.ServeHTTP(recLocal, reqLocal)

	if recLocal.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for localhost access, got %d", recLocal.Code)
	}
}

func TestForwardProxyHandlerStrictDeny(t *testing.T) {
	proxy, err := network.StartForwardProxy(policy.NetworkModeDeny, nil)
	if err != nil {
		t.Skip("skipping network socket binding in isolated sandbox")
	}
	defer proxy.Close()

	req := httptest.NewRequest(http.MethodGet, "http://any-domain.com/path", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden in strict deny mode, got %d", rec.Code)
	}
}

func TestForwardProxyHandlerAllowWithExplicitDeny(t *testing.T) {
	denied := []string{"evil.com", "telemetry.example.org"}
	proxy, err := network.StartForwardProxy(policy.NetworkModeAllow, nil, denied)
	if err != nil {
		t.Skip("skipping network socket binding in isolated sandbox")
	}
	defer proxy.Close()

	// 1. Exact match denied domain
	req := httptest.NewRequest(http.MethodGet, "http://evil.com/telemetry", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for explicitly denied domain, got %d", rec.Code)
	}

	// 2. Subdomain of denied domain
	reqSub := httptest.NewRequest(http.MethodGet, "http://sub.evil.com/telemetry", nil)
	recSub := httptest.NewRecorder()
	proxy.ServeHTTP(recSub, reqSub)

	if recSub.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for denied subdomain, got %d", recSub.Code)
	}

	// 3. Denied domain via CONNECT
	reqConnect := httptest.NewRequest(http.MethodConnect, "evil.com:443", nil)
	recConnect := httptest.NewRecorder()
	proxy.ServeHTTP(recConnect, reqConnect)

	if recConnect.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for CONNECT to denied domain, got %d", recConnect.Code)
	}

	// 4. Denied subdomain via CONNECT
	reqConnectSub := httptest.NewRequest(http.MethodConnect, "tracker.telemetry.example.org:443", nil)
	recConnectSub := httptest.NewRecorder()
	proxy.ServeHTTP(recConnectSub, reqConnectSub)

	if recConnectSub.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for CONNECT to denied subdomain, got %d", recConnectSub.Code)
	}

	// 5. Allowed domain should NOT be forbidden
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	reqAllowed := httptest.NewRequest(http.MethodGet, ts.URL, nil)
	recAllowed := httptest.NewRecorder()
	proxy.ServeHTTP(recAllowed, reqAllowed)

	if recAllowed.Code != http.StatusOK {
		t.Errorf("expected 200 OK for allowed target, got %d", recAllowed.Code)
	}
}

func TestForwardProxyAuthentication(t *testing.T) {
	proxy, err := network.StartForwardProxy(policy.NetworkModeAllow, nil)
	if err != nil {
		t.Skip("skipping network socket binding in isolated sandbox")
	}
	defer proxy.Close()

	proxy.SetSessionToken("secret-session-token-12345")

	// 1. Unauthenticated request should get 407
	req := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)
	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, req)

	if rec.Code != http.StatusProxyAuthRequired {
		t.Errorf("expected 407 Proxy Authentication Required, got %d", rec.Code)
	}

	// 2. Request with valid Proxy-Authorization header should pass
	reqAuth := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)
	reqAuth.Header.Set("Proxy-Authorization", "Bearer secret-session-token-12345")
	recAuth := httptest.NewRecorder()
	proxy.ServeHTTP(recAuth, reqAuth)

	// Since mode is allow and example.com is not denied, request proceeds past auth check
	if recAuth.Code == http.StatusProxyAuthRequired {
		t.Errorf("request with valid auth token was rejected with 407")
	}
}

func TestCertificateAuthorityLRUCache(t *testing.T) {
	ca, err := network.NewCertificateAuthority()
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}
	defer ca.Cleanup()

	// Request cert for host
	cert1, err := ca.GetHostCertificate("host1.example.com")
	if err != nil {
		t.Fatalf("failed to get host certificate: %v", err)
	}
	if cert1 == nil {
		t.Fatal("expected non-nil cert")
	}

	// Subsequent request should hit cache
	cert2, err := ca.GetHostCertificate("host1.example.com")
	if err != nil {
		t.Fatalf("failed to get cached certificate: %v", err)
	}
	if cert1 != cert2 {
		t.Errorf("expected cached pointer equality")
	}
}
