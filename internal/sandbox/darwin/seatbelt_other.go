//go:build !darwin

package darwin

import (
	"errors"
	"os/exec"

	"github.com/secretharbor/secretharbor/internal/compiler"
)

// DarwinSandbox stub for non-darwin platforms.
type DarwinSandbox struct {
	plan *compiler.CompiledPlan
}

// NewSandbox returns an error on non-darwin systems.
func NewSandbox(plan *compiler.CompiledPlan) (*DarwinSandbox, error) {
	return nil, errors.New("macOS seatbelt sandbox is only supported on darwin")
}

// Prepare stub for non-darwin systems.
func (s *DarwinSandbox) Prepare(plan *compiler.CompiledPlan) error {
	return errors.New("macOS seatbelt sandbox is only supported on darwin")
}

// Launch stub for non-darwin systems.
func (s *DarwinSandbox) Launch(command string, args []string, extraEnv []string) (*exec.Cmd, error) {
	return nil, errors.New("macOS seatbelt sandbox is only supported on darwin")
}

// Cleanup stub for non-darwin systems.
func (s *DarwinSandbox) Cleanup() {}
