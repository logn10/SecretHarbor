package linux

import (
	"testing"

	"github.com/secretharbor/secretharbor/internal/compiler"
	"github.com/secretharbor/secretharbor/internal/policy"
)

func TestLinuxSandboxBasics(t *testing.T) {
	plan := &compiler.CompiledPlan{
		ProjectDir: t.TempDir(),
		Network: compiler.NetworkPlan{
			Mode: policy.NetworkModeRestricted,
		},
		Filesystem: compiler.FilesystemPlan{
			Mode: policy.SecretModeAllow,
		},
	}

	sb, err := NewSandbox(plan)
	if err != nil {
		t.Fatalf("NewSandbox failed: %v", err)
	}

	res := CheckKernelCapabilities()
	_ = res

	ApplyProcessHardening()

	if err := SetupMountNamespace([]string{plan.ProjectDir}); err != nil {
		// May fail without root/unshared namespace, verify it runs without crashing
		t.Logf("SetupMountNamespace returned: %v", err)
	}

	_ = sb.Prepare(plan)
	sb.Cleanup()
}
