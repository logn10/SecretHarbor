package environment_test

import (
	"strings"
	"testing"

	"github.com/secretharbor/secretharbor/internal/environment"
	"github.com/secretharbor/secretharbor/internal/policy"
)

func TestSanitizeEnvironment(t *testing.T) {
	parentEnv := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/Users/test",
		"USER=testuser",
		"SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.fake/Listeners",
		"DOCKER_HOST=unix:///var/run/docker.sock",
		"KUBECONFIG=/Users/test/.kube/config",
		"STRIPE_SECRET_KEY=sk_live_REAL_STRIPE_SECRET",
		"DATABASE_URL=postgresql://real:real@db:5432/db",
		"PORT=8080",
	}

	cfg := &policy.EnvConfig{
		Mode:  policy.EnvModeSanitize,
		Allow: []string{"PATH", "HOME", "USER", "PORT"},
		Fake:  []string{"STRIPE_SECRET_KEY", "DATABASE_URL"},
		Deny:  []string{"AWS_SECRET_ACCESS_KEY"},
	}

	res := environment.Sanitize(parentEnv, cfg)

	envMap := make(map[string]string)
	for _, entry := range res.FinalEnv {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// 1. Verify safe variables preserved
	if envMap["PATH"] != "/usr/bin:/bin" {
		t.Errorf("expected PATH preserved, got %q", envMap["PATH"])
	}
	if envMap["USER"] != "testuser" {
		t.Errorf("expected USER preserved, got %q", envMap["USER"])
	}
	if envMap["PORT"] != "8080" {
		t.Errorf("expected PORT preserved, got %q", envMap["PORT"])
	}

	// 2. Verify privileged IPC endpoints purged
	if _, exists := envMap["SSH_AUTH_SOCK"]; exists {
		t.Errorf("SSH_AUTH_SOCK should be purged from final environment")
	}
	if _, exists := envMap["DOCKER_HOST"]; exists {
		t.Errorf("DOCKER_HOST should be purged from final environment")
	}
	if _, exists := envMap["KUBECONFIG"]; exists {
		t.Errorf("KUBECONFIG should be purged from final environment")
	}

	// 3. Verify secrets faked and never leaked
	stripeVal := envMap["STRIPE_SECRET_KEY"]
	if strings.Contains(stripeVal, "REAL_STRIPE_SECRET") {
		t.Errorf("real stripe secret leaked into final environment!")
	}
	if !strings.HasPrefix(stripeVal, "sk_test_secretharbor_fake_") {
		t.Errorf("expected synthetic stripe key, got %q", stripeVal)
	}

	dbVal := envMap["DATABASE_URL"]
	if strings.Contains(dbVal, "real:real") {
		t.Errorf("real database url leaked into final environment!")
	}
	if !strings.Contains(dbVal, "secretharbor_user") {
		t.Errorf("expected synthetic database url, got %q", dbVal)
	}
}

func TestCACertVariablesNotFaked(t *testing.T) {
	parentEnv := []string{
		"PATH=/usr/bin:/bin",
		"NODE_EXTRA_CA_CERTS=/tmp/secretharbor-ca-123.crt",
		"SSL_CERT_FILE=/tmp/secretharbor-ca-123.crt",
		"REQUESTS_CA_BUNDLE=/tmp/secretharbor-ca-123.crt",
	}

	cfg := &policy.EnvConfig{
		Mode: policy.EnvModeSanitize,
	}

	res := environment.Sanitize(parentEnv, cfg)
	for _, entry := range res.FinalEnv {
		if strings.HasPrefix(entry, "NODE_EXTRA_CA_CERTS=") {
			val := strings.TrimPrefix(entry, "NODE_EXTRA_CA_CERTS=")
			if val != "/tmp/secretharbor-ca-123.crt" {
				t.Errorf("NODE_EXTRA_CA_CERTS was unexpectedly faked/modified: %q", val)
			}
		}
		if strings.HasPrefix(entry, "SSL_CERT_FILE=") {
			val := strings.TrimPrefix(entry, "SSL_CERT_FILE=")
			if val != "/tmp/secretharbor-ca-123.crt" {
				t.Errorf("SSL_CERT_FILE was unexpectedly faked/modified: %q", val)
			}
		}
	}
}

func TestMergeEnv(t *testing.T) {
	base := []string{"FOO=bar", "BAZ=qux"}
	overrides := []string{"BAZ=new_qux", "ADDED=123"}

	merged := environment.MergeEnv(base, overrides)
	m := make(map[string]string)
	for _, entry := range merged {
		parts := strings.SplitN(entry, "=", 2)
		m[parts[0]] = parts[1]
	}

	if m["FOO"] != "bar" {
		t.Errorf("expected FOO=bar, got %q", m["FOO"])
	}
	if m["BAZ"] != "new_qux" {
		t.Errorf("expected BAZ=new_qux, got %q", m["BAZ"])
	}
	if m["ADDED"] != "123" {
		t.Errorf("expected ADDED=123, got %q", m["ADDED"])
	}
}

func TestMergeEnv_Duplicates(t *testing.T) {
	base := []string{"FOO=1", "BAR=2", "FOO=3"}
	overrides := []string{"BAR=4", "BAR=5"}

	merged := environment.MergeEnv(base, overrides)
	if len(merged) != 2 {
		t.Fatalf("expected 2 elements after deduplication, got %d: %v", len(merged), merged)
	}

	m := make(map[string]string)
	for _, entry := range merged {
		parts := strings.SplitN(entry, "=", 2)
		m[parts[0]] = parts[1]
	}

	if m["FOO"] != "3" {
		t.Errorf("expected FOO=3, got %q", m["FOO"])
	}
	if m["BAR"] != "5" {
		t.Errorf("expected BAR=5, got %q", m["BAR"])
	}
}

func TestSanitize_NilConfig(t *testing.T) {
	parentEnv := []string{
		"PATH=/bin",
		"SSH_AUTH_SOCK=/tmp/ssh.sock",
		"MY_SECRET_KEY=12345",
		"NORMAL_VAR=hello",
	}

	res := environment.Sanitize(parentEnv, nil)
	if res == nil {
		t.Fatal("expected non-nil result for nil config")
	}

	envMap := make(map[string]string)
	for _, entry := range res.FinalEnv {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	if _, exists := envMap["SSH_AUTH_SOCK"]; exists {
		t.Errorf("SSH_AUTH_SOCK should be stripped")
	}
	if envMap["NORMAL_VAR"] != "hello" {
		t.Errorf("NORMAL_VAR should be preserved, got %q", envMap["NORMAL_VAR"])
	}
}
