package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretharbor/secretharbor/internal/vault"
)

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestConfigCommands(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	// Initialize configuration
	if err := RunInit("shb", []string{}); err != nil {
		t.Fatalf("failed to init config: %v", err)
	}

	// 1. Test shb config show
	outShow := captureStdout(func() {
		if err := RunConfig("shb", []string{"show"}); err != nil {
			t.Errorf("shb config show failed: %v", err)
		}
	})
	if !strings.Contains(outShow, "SecretHarbor Configuration") {
		t.Errorf("expected header in config show, got: %s", outShow)
	}
	if !strings.Contains(outShow, "Protection: standard") {
		t.Errorf("expected Protection: standard, got: %s", outShow)
	}

	// 2. Test shb config --json
	outJSON := captureStdout(func() {
		if err := RunConfig("shb", []string{"--json"}); err != nil {
			t.Errorf("shb config --json failed: %v", err)
		}
	})
	var view EffectivePolicyView
	if err := json.Unmarshal([]byte(outJSON), &view); err != nil {
		t.Fatalf("failed to parse json config output: %v, raw: %s", err, outJSON)
	}
	if view.Protection != "standard" || view.Guard != "on" {
		t.Errorf("unexpected json view: %+v", view)
	}
	if view.Secrets["Default"] != "fake" {
		t.Errorf("expected Default: fake, got: %s", view.Secrets["Default"])
	}

	// 3. Test shb config source
	outSource := captureStdout(func() {
		if err := RunConfig("shb", []string{"source"}); err != nil {
			t.Errorf("shb config source failed: %v", err)
		}
	})
	if !strings.Contains(outSource, "Policy Provenance") {
		t.Errorf("expected Policy Provenance in source output, got: %s", outSource)
	}

	// 4. Test shb config check
	outCheck := captureStdout(func() {
		if err := RunConfig("shb", []string{"check"}); err != nil {
			t.Errorf("shb config check failed: %v", err)
		}
	})
	if !strings.Contains(outCheck, "Configuration is valid") {
		t.Errorf("expected Configuration is valid in check output, got: %s", outCheck)
	}

	// 5. Test shb config diff
	outDiff := captureStdout(func() {
		if err := RunConfig("shb", []string{"diff"}); err != nil {
			t.Errorf("shb config diff failed: %v", err)
		}
	})
	if !strings.Contains(outDiff, "Customizations") && !strings.Contains(outDiff, "identical") {
		t.Errorf("expected customizations or identical in diff with standard preset, got: %s", outDiff)
	}

	// 6. Test shb config edit - Agent Lockout
	origEnv := os.Getenv("SECRETHARBOR_SANDBOX")
	defer func() { _ = os.Setenv("SECRETHARBOR_SANDBOX", origEnv) }()
	_ = os.Setenv("SECRETHARBOR_SANDBOX", "1")

	err := RunConfig("shb", []string{"edit"})
	if err == nil {
		t.Errorf("expected error when editing config from sandbox, got nil")
	} else if !strings.Contains(err.Error(), "Permission denied: SecretHarbor policy is human-controlled") {
		t.Errorf("expected agent lockout permission denied error, got: %v", err)
	}
}

func TestPolicyCommands(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	if err := RunInit("shb", []string{}); err != nil {
		t.Fatalf("failed to init config: %v", err)
	}

	// 1. Test shb policy check
	outCheck := captureStdout(func() {
		if err := RunPolicy("shb", []string{"check"}); err != nil {
			t.Errorf("policy check failed: %v", err)
		}
	})
	if !strings.Contains(outCheck, "Configuration is valid") {
		t.Errorf("expected valid policy check, got: %s", outCheck)
	}

	// 2. Test shb policy explain .env
	outEnvFile := captureStdout(func() {
		if err := RunPolicy("shb", []string{"explain", ".env"}); err != nil {
			t.Errorf("policy explain .env failed: %v", err)
		}
	})
	if !strings.Contains(outEnvFile, "Resource: .env") {
		t.Errorf("expected Resource: .env in output, got: %s", outEnvFile)
	}
	if !strings.Contains(outEnvFile, "Agent read:   FAKE") {
		t.Errorf("expected Agent read: FAKE, got: %s", outEnvFile)
	}
	if !strings.Contains(outEnvFile, "Human:        ALLOW") {
		t.Errorf("expected Human: ALLOW, got: %s", outEnvFile)
	}

	// 3. Test shb policy explain DATABASE_URL
	outEnvVar := captureStdout(func() {
		if err := RunPolicy("shb", []string{"explain", "DATABASE_URL"}); err != nil {
			t.Errorf("policy explain DATABASE_URL failed: %v", err)
		}
	})
	if !strings.Contains(outEnvVar, "Resource: DATABASE_URL") {
		t.Errorf("expected Resource: DATABASE_URL, got: %s", outEnvVar)
	}
	if !strings.Contains(outEnvVar, "Agent visibility: FAKE") {
		t.Errorf("expected Agent visibility: FAKE, got: %s", outEnvVar)
	}

	// 4. Test shb policy explain --network api.stripe.com (allowed by default in allow mode)
	outNet := captureStdout(func() {
		if err := RunPolicy("shb", []string{"explain", "--network", "api.stripe.com"}); err != nil {
			t.Errorf("policy explain network failed: %v", err)
		}
	})
	if !strings.Contains(outNet, "Resource: api.stripe.com") {
		t.Errorf("expected network resource in output, got: %s", outNet)
	}
	if !strings.Contains(outNet, "ALLOWED") {
		t.Errorf("expected allowed network host by default, got: %s", outNet)
	}

	// 5. Test explicit network denial
	customYaml := `version: 1
protection: standard
network:
  mode: allow
  deny:
    - evil.com
`
	if err := os.WriteFile("secretharbor.yaml", []byte(customYaml), 0644); err != nil {
		t.Fatalf("failed to update config with deny: %v", err)
	}

	outNetDenied := captureStdout(func() {
		if err := RunPolicy("shb", []string{"explain", "--network", "evil.com"}); err != nil {
			t.Errorf("policy explain network failed: %v", err)
		}
	})
	if !strings.Contains(outNetDenied, "DENIED") {
		t.Errorf("expected denied network host for evil.com, got: %s", outNetDenied)
	}
}

func TestSecretCommands(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	if err := RunInit("shb", []string{}); err != nil {
		t.Fatalf("failed to init config: %v", err)
	}

	// Setup clean temporary vault
	vPath := filepath.Join(tmpDir, ".secretharbor", "vault.enc")
	_ = os.MkdirAll(filepath.Dir(vPath), 0700)
	v, err := vault.OpenVault(vPath)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("skipping vault test: creation restricted by outer sandbox environment: %v", err)
		}
		t.Fatalf("failed to open vault: %v", err)
	}
	vault.GlobalVault = v

	// 1. Test set secret
	if err := RunSecret("shb", []string{"set", "STRIPE_KEY", "sk_live_123456789"}); err != nil {
		t.Fatalf("secret set failed: %v", err)
	}

	// 2. Test list secret
	outList := captureStdout(func() {
		if err := RunSecret("shb", []string{"list"}); err != nil {
			t.Errorf("secret list failed: %v", err)
		}
	})
	if !strings.Contains(outList, "STRIPE_KEY") {
		t.Errorf("expected STRIPE_KEY in secret list, got: %s", outList)
	}
	// Verify zero-exposure: raw secret MUST NOT appear in list output
	if strings.Contains(outList, "sk_live_123456789") {
		t.Errorf("CRITICAL LEAK: raw secret found in secret list output")
	}

	// 3. Test status secret
	outStatus := captureStdout(func() {
		if err := RunSecret("shb", []string{"status", "STRIPE_KEY"}); err != nil {
			t.Errorf("secret status failed: %v", err)
		}
	})
	if !strings.Contains(outStatus, "STRIPE_KEY") {
		t.Errorf("expected STRIPE_KEY in status, got: %s", outStatus)
	}
	if !strings.Contains(outStatus, "Agent visibility: FAKE") {
		t.Errorf("expected Agent visibility: FAKE, got: %s", outStatus)
	}
	if strings.Contains(outStatus, "sk_live_123456789") {
		t.Errorf("CRITICAL LEAK: raw secret found in secret status output")
	}

	// 4. Test test secret
	outTest := captureStdout(func() {
		if err := RunSecret("shb", []string{"test", "STRIPE_KEY"}); err != nil {
			t.Errorf("secret test failed: %v", err)
		}
	})
	if !strings.Contains(outTest, "Verification passed") {
		t.Errorf("expected verification passed in test output, got: %s", outTest)
	}
	if strings.Contains(outTest, "sk_live_123456789") {
		t.Errorf("CRITICAL LEAK: raw secret found in secret test output")
	}

	// 5. Test delete secret
	if err := RunSecret("shb", []string{"delete", "STRIPE_KEY"}); err != nil {
		t.Fatalf("secret delete failed: %v", err)
	}
}

func TestTrustCommands(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	if err := RunInit("shb", []string{}); err != nil {
		t.Fatalf("failed to init config: %v", err)
	}

	// 1. Initial list (empty)
	outList := captureStdout(func() {
		if err := RunTrust("shb", []string{"list"}); err != nil {
			t.Errorf("trust list failed: %v", err)
		}
	})
	if !strings.Contains(outList, "No explicitly trusted") {
		t.Errorf("expected empty trusted list, got: %s", outList)
	}

	// 2. Add trusted process
	if err := RunTrust("shb", []string{"add", "npm"}); err != nil {
		t.Fatalf("trust add failed: %v", err)
	}

	// 3. List contains trusted process
	outList2 := captureStdout(func() {
		if err := RunTrust("shb", []string{"list"}); err != nil {
			t.Errorf("trust list failed: %v", err)
		}
	})
	if !strings.Contains(outList2, "npm") {
		t.Errorf("expected npm in trusted list, got: %s", outList2)
	}

	// 4. Remove trusted process
	if err := RunTrust("shb", []string{"remove", "npm"}); err != nil {
		t.Fatalf("trust remove failed: %v", err)
	}

	// 5. Verify removed
	outList3 := captureStdout(func() {
		if err := RunTrust("shb", []string{"list"}); err != nil {
			t.Errorf("trust list failed: %v", err)
		}
	})
	if !strings.Contains(outList3, "No explicitly trusted") {
		t.Errorf("expected empty trusted list after removal, got: %s", outList3)
	}
}

func TestCommandHelpAndRegistry(t *testing.T) {
	cmds := []string{"config", "policy", "secret", "trust", "doctor", "guard", "stop", "sessions"}
	for _, cmd := range cmds {
		helpOut := RenderHelp("shb", cmd)
		if !strings.Contains(helpOut, "NAME") || !strings.Contains(helpOut, "USAGE") || !strings.Contains(helpOut, "DESCRIPTION") {
			t.Errorf("incomplete help output for %s:\n%s", cmd, helpOut)
		}
		if !strings.Contains(helpOut, "shb "+cmd) {
			t.Errorf("expected usage with shb %s in help output", cmd)
		}
	}
}

func TestVersionOutputAudit(t *testing.T) {
	// 1. Human readable version audit
	outHuman := captureStdout(func() {
		printVersion("shb", []string{})
	})
	if !strings.Contains(outHuman, "SecretHarbor v") {
		t.Errorf("expected version header, got: %s", outHuman)
	}
	if !strings.Contains(outHuman, "Kernel:") {
		t.Errorf("expected Kernel info, got: %s", outHuman)
	}
	if !strings.Contains(outHuman, "Sandbox Driver:") {
		t.Errorf("expected Sandbox Driver info, got: %s", outHuman)
	}
	if !strings.Contains(outHuman, "Vault Storage:") {
		t.Errorf("expected Vault Storage info, got: %s", outHuman)
	}

	// 2. JSON formatted version audit
	outJSON := captureStdout(func() {
		printVersion("shb", []string{"--json"})
	})
	var vInfo VersionInfo
	if err := json.Unmarshal([]byte(outJSON), &vInfo); err != nil {
		t.Fatalf("failed to unmarshal version json: %v, raw: %s", err, outJSON)
	}
	if vInfo.Version == "" || vInfo.Kernel == "" || vInfo.SandboxDriver == "" {
		t.Errorf("missing fields in version json: %+v", vInfo)
	}
}

func TestRunLogsHonorsLimit(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SECRETHARBOR_DIR", tmpDir)

	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, `{"timestamp":"2026-01-01T00:00:00Z","agent":"a","operation":"launch","resource":"x","result":"ok"}`)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "audit.log"), []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(func() {
		if err := RunLogs("shb", []string{"2"}); err != nil {
			t.Errorf("RunLogs failed: %v", err)
		}
	})
	if !strings.Contains(out, "Last 2") {
		t.Errorf("expected limit of 2 to be honored, got: %s", out)
	}

	if err := RunLogs("shb", []string{"not-a-number"}); err == nil {
		t.Error("expected invalid log limit to be rejected")
	}
}

func TestConfigCheckExplicitFile(t *testing.T) {
	tmpDir := t.TempDir()
	badPath := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(badPath, []byte("version: 1\nprotection: standard\nnetwork:\n  mode: banana\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := RunConfig("shb", []string{"check", badPath}); err == nil {
		t.Error("expected config check to validate the explicitly provided file and fail")
	}
}

func TestGuardAgentLockout(t *testing.T) {
	t.Setenv("SECRETHARBOR_SANDBOX", "1")
	if err := RunGuard("shb", []string{"off", "-y"}); err == nil {
		t.Error("expected sandboxed agent to be denied guard off")
	}
	if err := RunGuard("shb", []string{"on"}); err == nil {
		t.Error("expected sandboxed agent to be denied guard on")
	}
}
