//go:build !linux

package linux

import (
	"os/exec"

	"github.com/secretharbor/secretharbor/internal/compiler"
)

// LinuxSandbox stub for non-Linux platforms.
type LinuxSandbox struct {
	plan *compiler.CompiledPlan
}

// NewSandbox initializes a stub Linux sandbox on non-Linux platforms.
func NewSandbox(plan *compiler.CompiledPlan) (*LinuxSandbox, error) {
	return &LinuxSandbox{
		plan: plan,
	}, nil
}

// KernelCheckResult reports the status of Linux namespace and isolation features.
type KernelCheckResult struct {
	UserNamespacesSupported bool
	DiagnosticMessage       string
}

// CheckKernelCapabilities returns stub check results for non-Linux platforms.
func CheckKernelCapabilities() KernelCheckResult {
	return KernelCheckResult{
		UserNamespacesSupported: false,
		DiagnosticMessage:       "Linux namespaces not supported on this platform",
	}
}

// Prepare stub for non-Linux platforms.
func (s *LinuxSandbox) Prepare(plan *compiler.CompiledPlan) error {
	s.plan = plan
	return nil
}

// Cleanup stub for non-Linux platforms.
func (s *LinuxSandbox) Cleanup() {}

// Launch executes using non-Linux launchPlatform stub.
func (s *LinuxSandbox) Launch(command string, args []string, extraEnv []string) (*exec.Cmd, error) {
	return s.launchPlatform(command, args, extraEnv)
}
