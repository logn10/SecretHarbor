package docs

import (
	"strings"
	"testing"
)

func TestGenerateMainManPage(t *testing.T) {
	man := GenerateMainManPage()
	if !strings.Contains(man, ".TH SHB 1") {
		t.Errorf("expected .TH SHB 1 header in main man page")
	}
	if !strings.Contains(man, "SecretHarbor") {
		t.Errorf("expected SecretHarbor mention in main man page")
	}
	if !strings.Contains(man, "config") || !strings.Contains(man, "policy") {
		t.Errorf("expected commands in main man page")
	}
}

func TestGenerateCommandManPages(t *testing.T) {
	commands := []string{"config", "policy", "secret", "trust", "run", "stop", "doctor"}
	for _, cmd := range commands {
		page, err := GenerateCommandManPage(cmd)
		if err != nil {
			t.Fatalf("failed to generate man page for %s: %v", cmd, err)
		}
		expectedHeader := ".TH SHB-" + strings.ToUpper(cmd) + " 1"
		if !strings.Contains(page, expectedHeader) {
			t.Errorf("expected %s in %s man page", expectedHeader, cmd)
		}
	}

	_, err := GenerateCommandManPage("nonexistent_command_xyz")
	if err == nil {
		t.Errorf("expected error for nonexistent command")
	}
}
