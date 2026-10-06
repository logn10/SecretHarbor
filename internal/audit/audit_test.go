package audit_test

import (
	"strings"
	"testing"

	"github.com/secretharbor/secretharbor/internal/audit"
)

func TestAuditRedaction(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "Authorization: Bearer sk-ant-api03-1234567890abcdef",
			expected: "Authorization: Bearer [REDACTED]",
		},
		{
			input:    "curl https://api.stripe.com -u sk_live_123456: token=my_secret_token",
			expected: "token=[REDACTED]",
		},
		{
			input:    "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----",
			expected: "-----BEGIN PRIVATE KEY----- [REDACTED] -----END PRIVATE KEY-----",
		},
		{
			input:    "agent --api-key sk-live-abc1234567890xyz --token secret123 -p mypassword",
			expected: "--api-key [REDACTED] --token [REDACTED] -p [REDACTED]",
		},
		{
			input:    `{"token": "secret_jwt_value", "password": "supersecretpassword"}`,
			expected: `"token":"[REDACTED]"`,
		},
		{
			input:    "Authorization: Basic dXNlcjpwYXNzd29yZA==",
			expected: "Authorization: Basic [REDACTED]",
		},
		{
			input:    "https://api.example.com/data?token=secrettoken123&api_key=456",
			expected: "?token=[REDACTED]&api_key=[REDACTED]",
		},
		{
			input:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expected: "[REDACTED JWT]",
		},
	}

	for _, tc := range tests {
		got := audit.Redact(tc.input)
		if !strings.Contains(got, tc.expected) {
			t.Errorf("Redact(%q) = %q; expected to contain %q", tc.input, got, tc.expected)
		}
	}
}

func TestReadLogs_Bounded(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("SECRETHARBOR_DIR", tmpDir)

	logger, err := audit.NewLogger()
	if err != nil {
		t.Fatalf("failed to create logger: %v", err)
	}

	for i := 0; i < 20; i++ {
		logger.Log("test-agent", "action", "resource", "success", "details")
	}

	events, err := audit.ReadLogs(5)
	if err != nil {
		t.Fatalf("ReadLogs failed: %v", err)
	}
	if len(events) != 5 {
		t.Errorf("expected 5 bounded events, got %d", len(events))
	}
}
