package broker_test

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/secretharbor/secretharbor/internal/broker"
)

func TestBrokerInjectionAuthorizedHost(t *testing.T) {
	b := broker.NewBroker()

	fakeToken := "sk_test_secretharbor_fake_123456"
	realSecret := "sk_live_super_secret_production_key"
	allowedHosts := []string{"api.stripe.com"}

	b.Register("STRIPE_KEY", fakeToken, realSecret, allowedHosts, 1*time.Hour)

	// 1. Request to approved host
	req, _ := http.NewRequest("POST", "https://api.stripe.com/v1/charges", strings.NewReader("amount=100"))
	req.Header.Set("Authorization", "Bearer "+fakeToken)

	injected := b.InterceptAndInject(req)
	if !injected {
		t.Fatal("expected credential injection on authorized host, got false")
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer "+realSecret {
		t.Errorf("expected injected real secret, got: %s", authHeader)
	}
}

func TestBrokerNoInjectionUnauthorizedHost(t *testing.T) {
	b := broker.NewBroker()

	fakeToken := "sk_test_secretharbor_fake_123456"
	realSecret := "sk_live_super_secret_production_key"
	allowedHosts := []string{"api.stripe.com"}

	b.Register("STRIPE_KEY", fakeToken, realSecret, allowedHosts, 1*time.Hour)

	// 2. Request to UNAPPROVED host (e.g. evil.com)
	req, _ := http.NewRequest("POST", "https://evil.com/exfiltrate", nil)
	req.Header.Set("Authorization", "Bearer "+fakeToken)

	injected := b.InterceptAndInject(req)
	if injected {
		t.Fatal("broker MUST NOT inject real secret into unauthorized destination!")
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer "+fakeToken {
		t.Errorf("expected fake token preserved, got: %s", authHeader)
	}
}

func TestBrokerExpiredCapability(t *testing.T) {
	b := broker.NewBroker()

	fakeToken := "sk_test_secretharbor_fake_expired"
	realSecret := "sk_live_expired_key"
	allowedHosts := []string{"api.stripe.com"}

	// Expired TTL
	b.Register("STRIPE_KEY", fakeToken, realSecret, allowedHosts, -1*time.Second)

	req, _ := http.NewRequest("POST", "https://api.stripe.com/v1/charges", nil)
	req.Header.Set("Authorization", "Bearer "+fakeToken)

	injected := b.InterceptAndInject(req)
	if injected {
		t.Fatal("broker MUST NOT inject real secret for expired capability")
	}
}

func TestBrokerDefaultTTL(t *testing.T) {
	b := broker.NewBroker()
	fakeToken := "fake_tok_default_ttl"
	realSecret := "real_secret_default_ttl"
	allowedHosts := []string{"api.example.com"}

	// Register with 0 TTL to use default TTL
	b.Register("KEY", fakeToken, realSecret, allowedHosts, 0)

	if !b.HasCapabilityForHost("api.example.com") {
		t.Errorf("expected capability to be active with default non-zero TTL")
	}

	req, _ := http.NewRequest("GET", "https://api.example.com/test", nil)
	req.Header.Set("Authorization", "Bearer "+fakeToken)
	injected := b.InterceptAndInject(req)
	if !injected {
		t.Errorf("expected injection with default TTL")
	}
}

func TestBrokerIPv6Host(t *testing.T) {
	b := broker.NewBroker()
	fakeToken := "fake_tok_ipv6"
	realSecret := "real_secret_ipv6"
	allowedHosts := []string{"[::1]:8080"}

	b.Register("KEY", fakeToken, realSecret, allowedHosts, 1*time.Hour)

	if !b.HasCapabilityForHost("[::1]:8080") {
		t.Errorf("expected HasCapabilityForHost to handle [::1]:8080")
	}
	if !b.HasCapabilityForHost("::1") {
		t.Errorf("expected HasCapabilityForHost to handle ::1")
	}

	req, _ := http.NewRequest("GET", "http://[::1]:8080/data", nil)
	req.Header.Set("Authorization", "Bearer "+fakeToken)
	injected := b.InterceptAndInject(req)
	if !injected {
		t.Errorf("expected injection on IPv6 host [::1]:8080")
	}
}

func TestBrokerBodyRestoration(t *testing.T) {
	b := broker.NewBroker()
	fakeToken := "fake_tok_body"
	realSecret := "real_secret_body"
	allowedHosts := []string{"api.example.com"}

	b.Register("KEY", fakeToken, realSecret, allowedHosts, 1*time.Hour)

	// Body without fake token
	originalContent := "field1=val1&field2=val2"
	req, _ := http.NewRequest("POST", "https://api.example.com/submit", strings.NewReader(originalContent))

	injected := b.InterceptAndInject(req)
	if injected {
		t.Errorf("expected no injection for body without token")
	}

	// Verify body is still readable and intact
	readBack, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("failed to read back body: %v", err)
	}
	if string(readBack) != originalContent {
		t.Errorf("body was corrupted or drained, got: %s", string(readBack))
	}
}
