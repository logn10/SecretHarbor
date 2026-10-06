//go:build linux

package linux

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/secretharbor/secretharbor/internal/compiler"
	"github.com/secretharbor/secretharbor/internal/policy"
	"github.com/secretharbor/secretharbor/internal/secrets"
)

// LinuxSandbox implements kernel-level isolation via Namespaces and Landlock LSM.
type LinuxSandbox struct {
	plan       *compiler.CompiledPlan
	virtualEnv *secrets.VirtualizedEnvironment
}

// NewSandbox initializes a Linux sandbox.
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

// CheckKernelCapabilities verifies if unprivileged user namespaces and isolation primitives are enabled.
func CheckKernelCapabilities() KernelCheckResult {
	res := KernelCheckResult{
		UserNamespacesSupported: true,
	}

	// Check Debian/Ubuntu unprivileged userns sysctl
	data, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone")
	if err == nil {
		val := strings.TrimSpace(string(data))
		if val == "0" {
			res.UserNamespacesSupported = false
			res.DiagnosticMessage = "unprivileged user namespaces disabled in kernel (/proc/sys/kernel/unprivileged_userns_clone = 0). Run: sudo sysctl -w kernel.unprivileged_userns_clone=1"
			return res
		}
	}

	// Check max user namespaces
	maxData, err := os.ReadFile("/proc/sys/user/max_user_namespaces")
	if err == nil {
		val := strings.TrimSpace(string(maxData))
		if val == "0" {
			res.UserNamespacesSupported = false
			res.DiagnosticMessage = "max user namespaces exhausted or set to 0. Run: sudo sysctl -w user.max_user_namespaces=15000"
			return res
		}
	}

	return res
}

// Prepare scans sensitive paths, virtualizes secrets, and generates shadow mount trees.
func (s *LinuxSandbox) Prepare(plan *compiler.CompiledPlan) error {
	s.plan = plan

	if check := CheckKernelCapabilities(); !check.UserNamespacesSupported {
		return fmt.Errorf("Linux sandbox kernel requirement not met: %s", check.DiagnosticMessage)
	}

	var allowExceptions, denyExceptions []string
	if plan.Policy != nil {
		allowExceptions = plan.Policy.Exceptions.Allow
		denyExceptions = plan.Policy.Exceptions.Deny
	}

	secretFiles, err := secrets.DetectSecretFilesInDir(
		plan.ProjectDir,
		allowExceptions,
		denyExceptions,
	)
	if err != nil {
		return fmt.Errorf("failed to detect secret files in %s: %w", plan.ProjectDir, err)
	}

	switch plan.Filesystem.Mode {
	case policy.SecretModeFake:
		// Files matching explicit deny exceptions are masked (denied), never faked.
		deniedSet := make(map[string]bool)
		for _, f := range secrets.FindMatchingFiles(plan.ProjectDir, denyExceptions) {
			deniedSet[f] = true
		}
		var fakeTargets []string
		for _, f := range secretFiles {
			if deniedSet[f] {
				s.plan.Filesystem.DeniedPaths = append(s.plan.Filesystem.DeniedPaths, f)
				continue
			}
			fakeTargets = append(fakeTargets, f)
		}
		if len(fakeTargets) > 0 {
			ve, err := secrets.PrepareVirtualization(fakeTargets)
			if err != nil {
				return fmt.Errorf("failed to prepare virtualization: %w", err)
			}
			s.virtualEnv = ve
			s.plan.Filesystem.FakeFiles = ve.FileMap
		}
	case policy.SecretModeDeny:
		// Deny mode masks detected secret files inside the mount namespace.
		s.plan.Filesystem.DeniedPaths = append(s.plan.Filesystem.DeniedPaths, secretFiles...)
	}

	return nil
}

// Cleanup removes ephemeral synthetic fake files (host files were never modified).
func (s *LinuxSandbox) Cleanup() {
	if s.virtualEnv != nil {
		s.virtualEnv.Cleanup()
	}
}

// Launch prepares sanitized environment, sets up namespace clone flags, and executes the command.
func (s *LinuxSandbox) Launch(command string, args []string, extraEnv []string) (*exec.Cmd, error) {
	return s.launchPlatform(command, args, extraEnv)
}
