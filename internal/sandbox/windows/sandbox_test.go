package windows

import (
	"testing"

	"github.com/secretharbor/secretharbor/internal/compiler"
)

func TestWindowsSandboxLifecycle(t *testing.T) {
	plan := &compiler.CompiledPlan{
		ProjectDir: t.TempDir(),
	}

	sb, err := NewSandbox(plan)
	if err != nil {
		t.Fatalf("NewSandbox failed: %v", err)
	}

	if err := sb.Prepare(plan); err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}

	cmd, err := sb.Launch("echo", []string{"test"}, nil)
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}
	if cmd == nil {
		t.Fatal("expected non-nil cmd")
	}

	sb.Cleanup()
}
