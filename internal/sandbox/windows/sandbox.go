package windows

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/secretharbor/secretharbor/internal/compiler"
	"github.com/secretharbor/secretharbor/internal/environment"
	"github.com/secretharbor/secretharbor/internal/fd"
	"github.com/secretharbor/secretharbor/internal/policy"
)

// WindowsSandbox enforces isolation on Windows using Job Objects.
type WindowsSandbox struct {
	plan *compiler.CompiledPlan
	job  *JobObject
}

func NewSandbox(plan *compiler.CompiledPlan) (*WindowsSandbox, error) {
	return &WindowsSandbox{plan: plan}, nil
}

func (s *WindowsSandbox) Prepare(plan *compiler.CompiledPlan) error {
	s.plan = plan
	job, err := CreateSandboxJob()
	if err != nil {
		return fmt.Errorf("windows sandbox initialization failed: %w", err)
	}
	s.job = job
	return nil
}

func (s *WindowsSandbox) Launch(command string, args []string, extraEnv []string) (*exec.Cmd, error) {
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

func (s *WindowsSandbox) Cleanup() {
	if s.job != nil {
		_ = s.job.Close()
		s.job = nil
	}
}
