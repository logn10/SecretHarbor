package cli

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/secretharbor/secretharbor/internal/agents"
	"github.com/secretharbor/secretharbor/internal/secrets"
	"github.com/secretharbor/secretharbor/internal/session"
)

// RunRestart cleanly stops a running agent session (or unprotected agent process)
// and relaunches it inside a fresh SecretHarbor sandbox.
func RunRestart(progName string, args []string) error {
	targetAgent := ""
	if len(args) > 0 {
		targetAgent = strings.ToLower(strings.TrimSpace(args[0]))
	}

	// 1. Scan running sessions and processes
	sessions, _ := session.List()
	runningProcs, _ := agents.ScanRunningProcesses()

	if targetAgent == "" {
		if len(sessions) == 1 {
			targetAgent = sessions[0].Agent
		} else if len(runningProcs) == 1 {
			targetAgent = runningProcs[0].AgentID
		} else if len(sessions) == 0 && len(runningProcs) == 0 {
			return fmt.Errorf("no running agent sessions or processes found to restart. Usage: %s restart <agent>", progName)
		} else {
			fmt.Println("Multiple agent processes detected. Specify which agent to restart:")
			for _, s := range sessions {
				fmt.Printf("  • %-12s [PROTECTED]   Session: %s (PID %d)\n", s.Agent, s.ID, s.PID)
			}
			for _, p := range runningProcs {
				if !p.Protected {
					fmt.Printf("  • %-12s [UNPROTECTED] PID %d\n", p.DisplayName, p.PID)
					if p.Hierarchy != nil {
						fmt.Print(p.Hierarchy.RenderTree("    "))
					}
				}
			}
			fmt.Printf("\nUsage: %s restart <agent>\n", progName)
			return nil
		}
	}

	normalizedTarget := strings.ToLower(targetAgent)
	foundAny := false

	// Stop any active SecretHarbor sessions for this agent
	for _, s := range sessions {
		if strings.ToLower(s.Agent) == normalizedTarget {
			foundAny = true
			fmt.Printf("Stopping active SecretHarbor session for %s (Session %s, PID %d)...\n", s.Agent, s.ID, s.PID)
			_ = session.StopSession(s)
			// Explicitly restore swapped secrets during restart (BUG-048)
			if s.ProjectDir != "" {
				_ = secrets.RestoreSwap(s.ProjectDir)
			}
			fmt.Printf("\033[32m✓ Stopped session %s\033[0m\n", s.ID)
		}
	}

	// Also restore swapped secrets for current working directory and any orphans
	cwd, _ := os.Getwd()
	if cwd != "" {
		_ = secrets.RestoreSwap(cwd)
	}
	_ = secrets.RestoreOrphanSwaps()

	// Stop any unprotected processes matching this agent
	for _, p := range runningProcs {
		if p != nil && strings.ToLower(p.AgentID) == normalizedTarget && !p.Protected {
			if p.PID <= 1 {
				continue
			}
			foundAny = true
			if !session.IsProcessAlive(p.PID) {
				continue
			}
			fmt.Printf("Stopping unprotected %s process (PID %d)...\n", p.DisplayName, p.PID)
			// Record process identity before signaling (BUG-018)
			origStart, origName, _ := session.GetProcessIdentity(p.PID)
			_ = killProcess(p.PID, syscall.SIGTERM)
			time.Sleep(500 * time.Millisecond)
			if session.IsProcessAlive(p.PID) {
				// Revalidate identity before sending SIGKILL!
				currStart, currName, _ := session.GetProcessIdentity(p.PID)
				if (origStart != "" && currStart != origStart) || (origName != "" && currName != origName) {
					// PID was reused, do not kill!
					continue
				}
				_ = killProcess(p.PID, syscall.SIGKILL)
			}
			fmt.Printf("\033[32m✓ Stopped unprotected %s (PID %d)\033[0m\n", p.DisplayName, p.PID)
		}
	}

	if !foundAny {
		fmt.Printf("No running process found for %q. Initializing fresh guarded session...\n", targetAgent)
	}

	fmt.Printf("Initializing SecretHarbor security boundary for %s...\n", targetAgent)
	fmt.Printf("\033[32m✓ Sandbox initialized. Starting %s...\033[0m\n\n", targetAgent)

	// Launch protected agent
	return RunAgent(progName, []string{targetAgent})
}
