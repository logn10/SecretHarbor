package compiler_test

import (
	"path/filepath"
	"testing"

	"github.com/secretharbor/secretharbor/internal/compiler"
	"github.com/secretharbor/secretharbor/internal/policy"
)

func TestCompile_NilPolicy(t *testing.T) {
	plan, err := compiler.Compile(nil, "", "")
	if err != nil {
		t.Fatalf("unexpected error compiling nil policy: %v", err)
	}
	if plan == nil {
		t.Fatal("expected non-nil plan")
	}
	if plan.Policy == nil {
		t.Fatal("expected default policy populated")
	}
	if plan.HomeDir == "/tmp" {
		t.Errorf("homeDir should not fallback to /tmp")
	}
}

func TestCompile_RulesAndHardening(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &policy.Config{
		Version:    1,
		Protection: policy.ProtectionStandard,
		Rules: []policy.SecretRule{
			{Secret: "CUSTOM_SECRET_VAR", Read: policy.SecretModeDeny},
			{Secret: "config/sensitive.key", Read: policy.SecretModeDeny},
		},
		Runtime: policy.RuntimeConfig{
			Allow: []string{"CUSTOM_SECRET_VAR"},
		},
		Sandbox: policy.SandboxConfig{
			Escape: policy.SandboxEscapeDeny,
		},
		Trusted: []string{"git", "docker"},
	}

	plan, err := compiler.Compile(cfg, filepath.Join(tmpDir, "secretharbor.yaml"), tmpDir)
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}

	if !plan.Process.DenySandboxEscape {
		t.Errorf("expected DenySandboxEscape to be true")
	}
	if len(plan.Process.TrustedProcesses) != 2 {
		t.Errorf("expected 2 trusted processes, got %v", plan.Process.TrustedProcesses)
	}
	if len(plan.Runtime.AllowedSecrets) != 1 || plan.Runtime.AllowedSecrets[0] != "CUSTOM_SECRET_VAR" {
		t.Errorf("expected runtime allowed secret, got %v", plan.Runtime.AllowedSecrets)
	}

	foundEnvDeny := false
	for _, d := range plan.Environment.DenyList {
		if d == "CUSTOM_SECRET_VAR" {
			foundEnvDeny = true
			break
		}
	}
	if !foundEnvDeny {
		t.Errorf("expected CUSTOM_SECRET_VAR in environment deny list")
	}
}

func TestCompile_RulesReadModesAppliedToEffectiveEnv(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &policy.Config{
		Version:    1,
		Protection: policy.ProtectionStandard,
		Rules: []policy.SecretRule{
			{Secret: "RULE_DENY_VAR", Read: policy.SecretModeDeny},
			{Secret: "RULE_FAKE_VAR", Read: policy.SecretModeFake},
			{Secret: "RULE_ALLOW_VAR", Read: policy.SecretModeAllow},
		},
	}
	policy.ApplyPresets(cfg)

	plan, err := compiler.Compile(cfg, filepath.Join(tmpDir, "secretharbor.yaml"), tmpDir)
	if err != nil {
		t.Fatalf("unexpected compile error: %v", err)
	}

	has := func(list []string, want string) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}
	if !has(plan.Environment.Effective.Deny, "RULE_DENY_VAR") {
		t.Errorf("expected RULE_DENY_VAR in effective deny list")
	}
	if !has(plan.Environment.Effective.Fake, "RULE_FAKE_VAR") {
		t.Errorf("expected RULE_FAKE_VAR in effective fake list")
	}
	if !has(plan.Environment.Effective.Allow, "RULE_ALLOW_VAR") {
		t.Errorf("expected RULE_ALLOW_VAR in effective allow list")
	}
}
