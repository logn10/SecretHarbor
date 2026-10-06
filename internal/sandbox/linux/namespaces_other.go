//go:build !linux

package linux

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/secretharbor/secretharbor/internal/environment"
	"github.com/secretharbor/secretharbor/internal/fd"
	"github.com/secretharbor/secretharbor/internal/policy"
)

func (s *LinuxSandbox) launchPlatform(command string, args []string, extraEnv []string) (*exec.Cmd, error) {
	rawEnv := append(os.Environ(), extraEnv...)
	envCfg := &s.plan.Environment.Effective
	if envCfg.Mode == "" && s.plan.Policy != nil {
		envCfg = &s.plan.Policy.Environment
	}
	res := environment.Sanitize(rawEnv, envCfg)
	finalEnv := append([]string(nil), res.FinalEnv...)

	if s.plan.IPC.DockerMode == policy.DockerIPCModeApproval {
		for _, extra := range extraEnv {
			if strings.HasPrefix(extra, "DOCKER_HOST=unix:///tmp/shb-d-") {
				finalEnv = append(finalEnv, extra)
				break
			}
		}
	}

	if err := fd.CloseUnexpectedFDs(nil); err != nil {
		return nil, fmt.Errorf("failed to sanitize file descriptors: %w", err)
	}

	cmd := exec.Command(command, args...)
	cmd.Dir = s.plan.ProjectDir
	cmd.Env = finalEnv
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd, nil
}

// SetupMountNamespace stub for non-Linux systems.
func SetupMountNamespace(allowedDirs []string) error {
	return nil
}

// ApplyProcessHardening stub for non-linux systems.
func ApplyProcessHardening() {}

// RunSandboxHelper is only implemented on Linux.
func RunSandboxHelper() error {
	return fmt.Errorf("linux sandbox helper is not available on this platform")
}
