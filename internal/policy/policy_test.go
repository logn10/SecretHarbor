package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/secretharbor/secretharbor/internal/policy"
)

func TestPolicyPresets(t *testing.T) {
	cfg := &policy.Config{
		Protection: policy.ProtectionStandard,
	}
	policy.ApplyPresets(cfg)

	if cfg.Secrets.Mode != policy.SecretModeFake {
		t.Errorf("expected secrets mode fake, got %s", cfg.Secrets.Mode)
	}
	if cfg.Environment.Mode != policy.EnvModeSanitize {
		t.Errorf("expected env mode sanitize, got %s", cfg.Environment.Mode)
	}
	if cfg.Network.Mode != policy.NetworkModeAllow {
		t.Errorf("expected network mode allow, got %s", cfg.Network.Mode)
	}
	if cfg.IPC.UnixSockets.Mode != policy.IPCModeDeny {
		t.Errorf("expected unix sockets mode deny, got %s", cfg.IPC.UnixSockets.Mode)
	}
}

func TestPolicyStrictPreset(t *testing.T) {
	cfg := &policy.Config{
		Protection: policy.ProtectionStrict,
	}
	policy.ApplyPresets(cfg)

	if cfg.Secrets.Mode != policy.SecretModeDeny {
		t.Errorf("expected strict secrets mode deny, got %s", cfg.Secrets.Mode)
	}
	if cfg.Network.Mode != policy.NetworkModeDeny {
		t.Errorf("expected strict network mode deny, got %s", cfg.Network.Mode)
	}
}

func TestPolicyValidationConflict(t *testing.T) {
	cfg := &policy.Config{
		Version:    1,
		Protection: policy.ProtectionStandard,
		Secrets:    policy.SecretsConfig{Mode: policy.SecretModeFake},
		Exceptions: policy.ExceptionsConfig{
			Allow: []string{".env.production"},
			Deny:  []string{".env.production"},
		},
	}

	err := policy.ValidatePolicy(cfg)
	if err == nil {
		t.Fatal("expected conflict error when path is in both allow and deny, got nil")
	}
}

func TestLoadPolicyFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "secretharbor.yaml")
	content := `
version: 1
protection: standard
secrets:
  mode: fake
exceptions:
  allow:
    - .env.example
  deny:
    - .env.prod
`
	if err := os.WriteFile(policyPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := policy.LoadPolicyFromFile(policyPath)
	if err != nil {
		t.Fatalf("unexpected error loading policy: %v", err)
	}

	if cfg.Version != 1 {
		t.Errorf("expected version 1, got %d", cfg.Version)
	}
	if len(cfg.Exceptions.Allow) != 1 || cfg.Exceptions.Allow[0] != ".env.example" {
		t.Errorf("unexpected allow exceptions: %v", cfg.Exceptions.Allow)
	}
}

func TestValidatePolicy_RejectsUnimplementedFeatures(t *testing.T) {
	base := func() *policy.Config {
		cfg := &policy.Config{Version: 1, Protection: policy.ProtectionStandard}
		policy.ApplyPresets(cfg)
		return cfg
	}

	escapeCfg := base()
	escapeCfg.Sandbox.Escape = policy.SandboxEscapeAllowOnce
	if err := policy.ValidatePolicy(escapeCfg); err == nil {
		t.Error("expected sandbox.escape=allow_once to be rejected as unimplemented")
	}

	containerCfg := base()
	containerCfg.IPC.Docker.AllowedContainers = []string{"my-container"}
	if err := policy.ValidatePolicy(containerCfg); err == nil {
		t.Error("expected ipc.docker.allowed_containers to be rejected as unsupported")
	}

	invalidNetwork := base()
	invalidNetwork.Network.Mode = policy.NetworkMode("banana")
	if err := policy.ValidatePolicy(invalidNetwork); err == nil {
		t.Error("expected invalid network mode to be rejected")
	}
}
