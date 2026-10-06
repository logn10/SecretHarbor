package secrets_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretharbor/secretharbor/internal/secrets"
)

func TestSecretDetection(t *testing.T) {
	allow := []string{".env.example"}
	deny := []string{"custom-secrets.txt"}

	tests := []struct {
		path     string
		expected bool
	}{
		{".env", true},
		{".env.local", true},
		{"id_rsa", true},
		{"server.pem", true},
		{"credentials.json", true},
		{".env.example", false},      // Explicitly allowed
		{"custom-secrets.txt", true}, // Explicitly denied
		{"main.go", false},
		{"package.json", false},
		{"README.md", false},
	}

	for _, tc := range tests {
		got := secrets.IsSecretFile(tc.path, ".", allow, deny)
		if got != tc.expected {
			t.Errorf("IsSecretFile(%q) = %v; expected %v", tc.path, got, tc.expected)
		}
	}
}

func TestFakeValueGeneration(t *testing.T) {
	tests := []struct {
		keyName string
		prefix  string
	}{
		{"STRIPE_SECRET_KEY", "sk_test_secretharbor_fake_"},
		{"OPENAI_API_KEY", "sk-proj-secretharbor-fake-"},
		{"ANTHROPIC_API_KEY", "sk-ant-api03-secretharbor-fake-"},
		{"GITHUB_TOKEN", "ghp_secretharbor_fake_"},
		{"AWS_ACCESS_KEY_ID", "AKIAFAKEHARBOR"},
		{"DATABASE_URL", "postgresql://secretharbor_user:fake_password@localhost:5432/fake_db"},
		{"APP_JWT_SECRET", "eyJ"},
		{"CUSTOM_UNKNOWN_KEY", "secretharbor_fake_"},
	}

	for _, tc := range tests {
		val := secrets.GenerateFakeValue(tc.keyName)
		if !strings.HasPrefix(val, tc.prefix) {
			t.Errorf("GenerateFakeValue(%q) = %q; expected prefix %q", tc.keyName, val, tc.prefix)
		}
	}
}

func TestVirtualizeEnvContent(t *testing.T) {
	input := `# Project Environment Variables
PORT=3000
NODE_ENV=development
DATABASE_URL=postgresql://real_user:super_secret_password@db.internal:5432/prod
STRIPE_KEY=sk_live_1234567890abcdef
`
	r := strings.NewReader(input)
	output, err := secrets.VirtualizeEnvContent(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(output, "PORT=3000") {
		t.Errorf("expected PORT=3000 preserved, got:\n%s", output)
	}
	if !strings.Contains(output, "NODE_ENV=development") {
		t.Errorf("expected NODE_ENV=development preserved, got:\n%s", output)
	}
	if strings.Contains(output, "super_secret_password") {
		t.Errorf("real database password leaked in virtualized content!")
	}
	if strings.Contains(output, "sk_live_1234567890abcdef") {
		t.Errorf("real stripe key leaked in virtualized content!")
	}
	if !strings.Contains(output, "sk_test_secretharbor_fake_") {
		t.Errorf("expected synthetic stripe key in output, got:\n%s", output)
	}
}

func TestIsLikelySecretVar(t *testing.T) {
	// BUG-019: Ensure non-secrets with substring collisions are NOT faked
	nonSecrets := []string{
		"MONKEY",
		"AUTHORS",
		"PASSENGER",
		"KEYBOARD",
		"BASALT",
		"PWD",
		"OLDPWD",
		"PORT",
		"NODE_ENV",
		"HOME",
		"PATH",
		"SHELL",
		"USER",
		"TMPDIR",
	}
	for _, k := range nonSecrets {
		if secrets.IsLikelySecretVar(k) {
			t.Errorf("IsLikelySecretVar(%q) = true; expected false (non-secret should not be faked)", k)
		}
	}

	// Sensitive variables that must be identified
	secretVars := []string{
		"STRIPE_KEY",
		"STRIPE_SECRET_KEY",
		"OPENAI_API_KEY",
		"API_KEY",
		"AUTH_TOKEN",
		"DATABASE_URL",
		"DB_PASSWORD",
		"AWS_SECRET_ACCESS_KEY",
		"GITHUB_TOKEN",
		"CLIENT_SECRET",
		"PRIVATE_KEY",
		"MY_APIKEY",
		"APP_SIGNATURE",
		"SESSION_SALT",
	}
	for _, k := range secretVars {
		if !secrets.IsLikelySecretVar(k) {
			t.Errorf("IsLikelySecretVar(%q) = false; expected true", k)
		}
	}
}

func TestVirtualizeEnvContent_MultilineAndQuoted(t *testing.T) {
	// BUG-001 & BUG-062: Multiline secrets in single/double quotes, unquoted continuations,
	// backticks, export prefix, CRLF, and escaped quotes
	input := "PORT=3000\r\n" +
		"MONKEY=banana\r\n" +
		"AUTHORS=alice,bob\r\n" +
		"PASSENGER=yes\r\n" +
		"KEYBOARD=ansi\r\n" +
		"BASALT=rock\r\n" +
		"PWD=/workspace/app\r\n" +
		"export API_KEY=\"secret-api-key-12345\"\r\n" +
		"PRIVATE_KEY=\"-----BEGIN RSA PRIVATE KEY-----\r\n" +
		"REAL_RSA_KEY_LINE_ONE\r\n" +
		"REAL_RSA_KEY_LINE_TWO\r\n" +
		"-----END RSA PRIVATE KEY-----\"\r\n" +
		"SINGLE_QUOTED_SECRET='-----BEGIN CERTIFICATE-----\r\n" +
		"REAL_CERT_LINE_ONE\r\n" +
		"-----END CERTIFICATE-----'\r\n" +
		"BACKTICK_TOKEN=`eyJhbGciOiJIUzI1NiJ9\r\n" +
		"REAL_JWT_PAYLOAD_DATA\r\n" +
		"REAL_JWT_SIGNATURE`\r\n" +
		"UNQUOTED_SECRET=continuation_part_one_secret\\\r\n" +
		"continuation_part_two_secret\r\n" +
		"ESCAPED_VAR=\"hello \\\"world\\\"\"\r\n"

	r := strings.NewReader(input)
	output, err := secrets.VirtualizeEnvContent(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify non-secrets are kept intact
	if !strings.Contains(output, "PORT=3000") {
		t.Error("PORT=3000 should be preserved")
	}
	if !strings.Contains(output, "MONKEY=banana") {
		t.Error("MONKEY=banana should be preserved")
	}
	if !strings.Contains(output, "AUTHORS=alice,bob") {
		t.Error("AUTHORS=alice,bob should be preserved")
	}
	if !strings.Contains(output, "PASSENGER=yes") {
		t.Error("PASSENGER=yes should be preserved")
	}
	if !strings.Contains(output, "KEYBOARD=ansi") {
		t.Error("KEYBOARD=ansi should be preserved")
	}
	if !strings.Contains(output, "BASALT=rock") {
		t.Error("BASALT=rock should be preserved")
	}
	if !strings.Contains(output, "PWD=/workspace/app") {
		t.Error("PWD=/workspace/app should be preserved")
	}
	if !strings.Contains(output, "ESCAPED_VAR=\"hello \\\"world\\\"\"") {
		t.Errorf("escaped non-secret should be preserved, got:\n%s", output)
	}

	// Verify export prefix is preserved on faked secret
	if !strings.Contains(output, "export API_KEY=secretharbor_fake_") {
		t.Errorf("export prefix missing on faked API_KEY in output:\n%s", output)
	}

	// BUG-001: Verify NO subsequent lines of real multiline secrets leaked!
	leakChecks := []string{
		"REAL_RSA_KEY_LINE_ONE",
		"REAL_RSA_KEY_LINE_TWO",
		"REAL_CERT_LINE_ONE",
		"REAL_JWT_PAYLOAD_DATA",
		"REAL_JWT_SIGNATURE",
		"continuation_part_one_secret",
		"continuation_part_two_secret",
		"secret-api-key-12345",
	}
	for _, leak := range leakChecks {
		if strings.Contains(output, leak) {
			t.Fatalf("CRITICAL LEAK: real secret material %q found in output:\n%s", leak, output)
		}
	}
}

func TestDetectorProtectedCredentials(t *testing.T) {
	// BUG-014: Protect claimed credentials in standard fake mode
	tests := []struct {
		path     string
		expected bool
	}{
		{"~/.config/gcloud/credentials.json", true},
		{".config/gcloud/credentials.json", true},
		{"~/.netrc", true},
		{".netrc", true},
		{".npmrc", true},
		{".pypirc", true},
		{"~/.kube/config", true},
		{".kube/config", true},
		{"~/.git-credentials", true},
		{".git-credentials", true},
		{".aws/credentials", true},
		{".aws/config", true},
		{".ssh/id_rsa", true},
		{".gnupg/pubring.kbx", true},
	}

	for _, tc := range tests {
		got := secrets.IsSecretFile(tc.path, "", nil, nil)
		if got != tc.expected {
			t.Errorf("IsSecretFile(%q) = %v; expected %v", tc.path, got, tc.expected)
		}
	}
}

func TestDetectSecretFilesInDir_SkipsCommonBuildDirs(t *testing.T) {
	// BUG-063: Skip target, dist, build, .next, venv, .venv, __pycache__, bin, obj
	tmpDir := t.TempDir()

	skipDirs := []string{
		"target", "dist", "build", ".next", "venv", ".venv", "__pycache__", "bin", "obj",
		".git", ".secretharbor", "node_modules", "vendor",
	}

	for _, d := range skipDirs {
		dirPath := filepath.Join(tmpDir, d)
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			t.Fatal(err)
		}
		// Place a secret file inside each ignored dir
		if err := os.WriteFile(filepath.Join(dirPath, ".env"), []byte("SECRET=ignored"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	// Place one valid secret file in project root
	rootSecret := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(rootSecret, []byte("SECRET=root"), 0600); err != nil {
		t.Fatal(err)
	}

	found, err := secrets.DetectSecretFilesInDir(tmpDir, nil, nil)
	if err != nil {
		t.Fatalf("DetectSecretFilesInDir failed: %v", err)
	}

	if len(found) != 1 || found[0] != rootSecret {
		t.Fatalf("expected only root secret found, got: %v", found)
	}
}
