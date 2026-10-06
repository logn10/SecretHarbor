package sandbox

import (
	"testing"

	"github.com/secretharbor/secretharbor/internal/compiler"
)

func TestNewSandbox(t *testing.T) {
	plan := &compiler.CompiledPlan{
		ProjectDir: t.TempDir(),
	}

	sb, err := New(plan)
	if err != nil {
		t.Fatalf("New sandbox failed: %v", err)
	}
	if sb == nil {
		t.Fatal("expected non-nil sandbox")
	}
}
