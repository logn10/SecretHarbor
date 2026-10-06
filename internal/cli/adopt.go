package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/secretharbor/secretharbor/internal/agents"
	"github.com/secretharbor/secretharbor/internal/session"
)

// RunAdopt discovers unprotected currently-running agent processes and offers to safely restart them under SecretHarbor.
func RunAdopt(progName string, args []string) error {
	autoConfirm := false
	for _, arg := range args {
		if arg == "-y" || arg == "--yes" {
			autoConfirm = true
		}
	}

	running, err := agents.ScanRunningProcesses()
	if err != nil {
		return fmt.Errorf("failed to scan running processes: %w", err)
	}

	groups := agents.GroupAgentProcesses(running)
	var unprotected []*agents.RunningAppGroup
	totalProcs := 0
	for _, g := range groups {
		if !g.Protected {
			unprotected = append(unprotected, g)
			totalProcs += len(g.AllPIDs)
		}
	}

	if len(unprotected) == 0 {
		fmt.Println("No unprotected agent processes found.")
		sessions, _ := session.List()
		if len(sessions) > 0 {
			fmt.Printf("All %d active agent sessions are already protected by SecretHarbor.\n", len(sessions))
		}
		return nil
	}

	fmt.Println("SecretHarbor Agent Adoption")
	fmt.Println(stringsRepeat("─", 50))
	if totalProcs > len(unprotected) {
		fmt.Printf("Found %d agent application(s) (%d total processes) running outside the security boundary:\n\n", len(unprotected), totalProcs)
	} else {
		fmt.Printf("Found %d agent application(s) running outside the security boundary:\n\n", len(unprotected))
	}

	for _, g := range unprotected {
		if g == nil || g.RootProcess == nil {
			continue
		}

		if len(g.AllPIDs) > 1 {
			fmt.Printf("  • %-12s PID %-7d (%d processes) %s\n", g.DisplayName, g.RootProcess.PID, len(g.AllPIDs), g.RootProcess.Command)
		} else {
			fmt.Printf("  • %-12s PID %-7d %s\n", g.DisplayName, g.RootProcess.PID, g.RootProcess.Command)
		}
		fmt.Println("    Status:     \033[33mUNPROTECTED\033[0m (started before SecretHarbor)")
		fmt.Println("    Constraint: An active process cannot be retroactively sandboxed safely.")
		fmt.Println("                A security boundary must exist before the process starts.")
		if g.RootProcess.Hierarchy != nil {
			fmt.Println("    Process Hierarchy:")
			fmt.Print(g.RootProcess.Hierarchy.RenderTree("      "))
		}
		if len(g.HelperProcesses) > 0 {
			fmt.Printf("    Helper Processes (%d): ", len(g.HelperProcesses))
			var helperNames []string
			for i, h := range g.HelperProcesses {
				if i >= 3 {
					helperNames = append(helperNames, fmt.Sprintf("+%d more", len(g.HelperProcesses)-3))
					break
				}
				helperNames = append(helperNames, fmt.Sprintf("PID %d", h.PID))
			}
			fmt.Println(strings.Join(helperNames, ", "))
		}
		fmt.Println()

		if !autoConfirm {
			if !isInputTerminal() {
				fmt.Printf("Skipped %s (non-interactive terminal). Process remains unprotected.\n\n", g.DisplayName)
				continue
			}

			if len(g.AllPIDs) > 1 {
				fmt.Printf("Restart %s (%d processes) under SecretHarbor protection now? [y/N/all/skip] ", g.DisplayName, len(g.AllPIDs))
			} else {
				fmt.Printf("Restart %s under SecretHarbor protection now? [y/N/all/skip] ", g.DisplayName)
			}

			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))

			if input == "all" || input == "a" {
				autoConfirm = true
			} else if input == "skip" || input == "s" {
				fmt.Printf("Skipped %s and all remaining processes.\n\n", g.DisplayName)
				break
			} else if input != "y" && input != "yes" {
				if len(g.AllPIDs) > 1 {
					fmt.Printf("Skipped %s (%d processes). Processes remain unprotected.\n\n", g.DisplayName, len(g.AllPIDs))
				} else {
					fmt.Printf("Skipped %s. Process remains unprotected.\n\n", g.DisplayName)
				}
				continue
			}
		}

		if g.RootProcess.PID <= 1 || g.RootProcess.PID == os.Getpid() {
			continue
		}

		if !session.IsProcessAlive(g.RootProcess.PID) {
			fmt.Printf("Process %s (PID %d) is no longer running.\n", g.DisplayName, g.RootProcess.PID)
			continue
		}

		// Terminate unprotected processes in the group cleanly
		if len(g.AllPIDs) > 1 {
			fmt.Printf("Stopping unprotected %s (%d processes)...\n", g.DisplayName, len(g.AllPIDs))
		} else {
			fmt.Printf("Stopping unprotected %s process (PID %d)...\n", g.DisplayName, g.RootProcess.PID)
		}

		// Record identities before signaling to prevent PID-reuse kill (BUG-018)
		type procIdent struct {
			start string
			name  string
		}
		idents := make(map[int]procIdent)
		for _, pid := range g.AllPIDs {
			s, n, _ := session.GetProcessIdentity(pid)
			idents[pid] = procIdent{start: s, name: n}
		}

		for _, pid := range g.AllPIDs {
			if pid > 1 && pid != os.Getpid() {
				_ = killProcess(pid, syscall.SIGTERM)
			}
		}
		time.Sleep(500 * time.Millisecond)
		for _, pid := range g.AllPIDs {
			if pid > 1 && pid != os.Getpid() && session.IsProcessAlive(pid) {
				expected := idents[pid]
				if expected.start != "" || expected.name != "" {
					currStart, currName, _ := session.GetProcessIdentity(pid)
					if (expected.start != "" && currStart != expected.start) || (expected.name != "" && currName != expected.name) {
						// PID was reused, do NOT kill!
						continue
					}
				}
				_ = killProcess(pid, syscall.SIGKILL)
			}
		}

		if len(g.AllPIDs) > 1 {
			fmt.Printf("\033[32m✓ Stopped %s (%d processes)\033[0m\n", g.DisplayName, len(g.AllPIDs))
		} else {
			fmt.Printf("\033[32m✓ Stopped %s (PID %d)\033[0m\n", g.DisplayName, g.RootProcess.PID)
		}

		fmt.Printf("Restarting %s inside SecretHarbor sandbox...\n", g.DisplayName)

		// Check if the adopted process was a GUI desktop app
		isGUI := g.IsGUIApp()
		exe := agents.ExtractExecutableFromCommand(g.RootProcess.Command)
		origArgs := g.RootProcess.Args
		var cmdArgs []string
		if isGUI && exe != "" {
			cmdArgs = []string{exe}
		} else {
			cmdArgs = []string{g.AgentID}
		}
		if len(origArgs) > 1 {
			cmdArgs = append(cmdArgs, origArgs[1:]...)
		}

		// Adopt every unprotected group; multiple (or automatic) adoptions run as
		// background supervisors so each agent keeps its own enforcement infrastructure.
		if autoConfirm || len(unprotected) > 1 {
			if err := RunAgent(progName, append([]string{"-d"}, cmdArgs...)); err != nil {
				return err
			}
			continue
		}
		return RunAgent(progName, cmdArgs)
	}

	return nil
}
