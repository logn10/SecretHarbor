package sandbox

import (
	"os/exec"
	"runtime"

	"github.com/secretharbor/secretharbor/internal/compiler"
	"github.com/secretharbor/secretharbor/internal/sandbox/darwin"
	"github.com/secretharbor/secretharbor/internal/sandbox/linux"
	"github.com/secretharbor/secretharbor/internal/sandbox/windows"
)

// Sandbox defines the OS-level isolation boundary interface.
type Sandbox interface {
	Prepare(plan *compiler.CompiledPlan) error
	Launch(command string, args []string, extraEnv []string) (*exec.Cmd, error)
	Cleanup()
}

// SandboxHelperArg is the hidden CLI subcommand used to apply kernel restrictions
// inside the sandboxed child process.
const SandboxHelperArg = linux.SandboxHelperArg

// RunSandboxHelper applies kernel enforcement for the current process and execs the
// target command. It is invoked only through the hidden SandboxHelperArg subcommand.
func RunSandboxHelper() error {
	return linux.RunSandboxHelper()
}

// New creates an appropriate sandbox instance for the current host operating system.
func New(plan *compiler.CompiledPlan) (Sandbox, error) {
	switch runtime.GOOS {
	case "darwin":
		return darwin.NewSandbox(plan)
	case "linux":
		return linux.NewSandbox(plan)
	case "windows":
		return windows.NewSandbox(plan)
	default:
		// Fallback to darwin/posix generic isolation
		return darwin.NewSandbox(plan)
	}
}
