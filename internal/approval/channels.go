package approval

import (
	"bufio"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// PromptOSDialog invokes the native desktop environment's modal or notification dialog.
func PromptOSDialog(req *Request) (bool, error) {
	if os.Getenv("SECRETHARBOR_DISABLE_OS_DIALOG") == "1" {
		return false, fmt.Errorf("desktop dialog disabled by SECRETHARBOR_DISABLE_OS_DIALOG")
	}
	switch runtime.GOOS {
	case "darwin":
		return promptMacOSDialog(req)
	case "linux":
		return promptLinuxDialog(req)
	case "windows":
		return promptWindowsDialog(req)
	default:
		return false, fmt.Errorf("unsupported OS for desktop dialog: %s", runtime.GOOS)
	}
}

func promptMacOSDialog(req *Request) (bool, error) {
	script := fmt.Sprintf(
		`tell application "System Events"
			activate
			display dialog "SecretHarbor Escalation Request\n\nAgent: %s (PID %d)\nOperation: %s\nDetails: %s\n\nApprove via CLI: shb approve %s" with title "SecretHarbor Security Boundary" buttons {"Deny", "Allow Once"} default button "Deny" with icon caution giving up after 30
		end tell`,
		escapeAppleScript(req.AgentName),
		req.PID,
		escapeAppleScript(req.Capability),
		escapeAppleScript(req.Details),
		escapeAppleScript(req.ID),
	)

	cmd := exec.Command("osascript", "-e", script)
	output, err := cmd.CombinedOutput()
	str := string(output)

	if strings.Contains(str, "button returned:Allow Once") {
		return true, nil
	}
	if strings.Contains(str, "button returned:Deny") || strings.Contains(str, "gave up:true") || strings.Contains(str, "User canceled") || strings.Contains(str, "-128") {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("osascript execution failed: %s (%w)", strings.TrimSpace(str), err)
	}

	return false, nil
}

func promptLinuxDialog(req *Request) (bool, error) {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return false, fmt.Errorf("no graphical display available on Linux (DISPLAY/WAYLAND_DISPLAY unset)")
	}

	// Try zenity if available
	if zenityPath, err := exec.LookPath("zenity"); err == nil {
		text := fmt.Sprintf("SecretHarbor Escalation Request\n\nAgent: %s (PID %d)\nOperation: %s\nDetails: %s\n\nApprove via CLI: shb approve %s",
			req.AgentName, req.PID, req.Capability, req.Details, req.ID)
		cmd := exec.Command(zenityPath, "--question", "--timeout=30", "--title=SecretHarbor Security", "--text="+text, "--ok-label=Allow Once", "--cancel-label=Deny")
		out, runErr := cmd.CombinedOutput()
		if runErr == nil {
			return true, nil
		}
		if exitErr, ok := runErr.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("zenity failed: %s (%w)", strings.TrimSpace(string(out)), runErr)
	}

	// Try kdialog
	if kdialogPath, err := exec.LookPath("kdialog"); err == nil {
		text := fmt.Sprintf("SecretHarbor Escalation Request\n\nAgent: %s (PID %d)\nOperation: %s\nDetails: %s\n\nApprove via CLI: shb approve %s",
			req.AgentName, req.PID, req.Capability, req.Details, req.ID)
		cmd := exec.Command(kdialogPath, "--yesno", text, "--title", "SecretHarbor Security", "--yes-label", "Allow Once", "--no-label", "Deny")
		out, runErr := cmd.CombinedOutput()
		if runErr == nil {
			return true, nil
		}
		if exitErr, ok := runErr.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("kdialog failed: %s (%w)", strings.TrimSpace(string(out)), runErr)
	}

	return false, fmt.Errorf("no desktop dialog tool (zenity/kdialog) available on Linux")
}

func promptWindowsDialog(req *Request) (bool, error) {
	// Pass agent-controlled fields safely via environment variables to avoid PowerShell command injection (BUG-037)
	psScript := `
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
$msg = "Agent " + $env:SHB_REQ_AGENT + " (PID " + $env:SHB_REQ_PID + ") requests " + $env:SHB_REQ_CAP + ": " + $env:SHB_REQ_DETAILS
$res = [System.Windows.Forms.MessageBox]::Show($msg, "SecretHarbor Security", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
if ($res -eq [System.Windows.Forms.DialogResult]::Yes) { exit 0 } else { exit 1 }
`

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("SHB_REQ_AGENT=%s", req.AgentName),
		fmt.Sprintf("SHB_REQ_PID=%d", req.PID),
		fmt.Sprintf("SHB_REQ_CAP=%s", req.Capability),
		fmt.Sprintf("SHB_REQ_DETAILS=%s", req.Details),
	)
	if err := cmd.Run(); err == nil {
		return true, nil
	}
	return false, nil
}

func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

// serveSocket handles secondary CLI commands (secretharbor approve / pending / deny) over Unix domain socket.
func (m *Manager) serveSocket() {
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			select {
			case <-m.stopChan:
				return
			default:
				return
			}
		}
		go m.handleSocketConn(conn)
	}
}

func (m *Manager) handleSocketConn(conn net.Conn) {
	defer conn.Close()

	// Check peer credentials (SO_PEERCRED on Linux, LOCAL_PEERPID on macOS) (BUG-003)
	// Ensure caller PID is not the sandboxed agent PID or descendant
	if callerPID, err := getPeerPID(conn); err == nil && callerPID > 0 {
		if m.isCallerUnauthorized(callerPID) {
			_, _ = conn.Write([]byte("ERROR: Unauthorized caller PID (sandboxed agent)\n"))
			return
		}
	}

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}
	line := strings.TrimSpace(scanner.Text())

	// Require secret authorization token generated at manager start (BUG-003)
	if m.authToken != "" {
		if strings.HasPrefix(line, "AUTH ") {
			token := strings.TrimSpace(strings.TrimPrefix(line, "AUTH "))
			if subtle.ConstantTimeCompare([]byte(token), []byte(m.authToken)) != 1 {
				_, _ = conn.Write([]byte("ERROR: Unauthorized (invalid authorization token)\n"))
				return
			}
			if !scanner.Scan() {
				_, _ = conn.Write([]byte("OK: Authenticated\n"))
				return
			}
			line = strings.TrimSpace(scanner.Text())
		} else {
			_, _ = conn.Write([]byte("ERROR: Unauthorized (authentication token required)\n"))
			return
		}
	}

	parts := strings.SplitN(line, " ", 2)
	cmd := strings.ToUpper(parts[0])

	switch cmd {
	case "LIST":
		list := m.ListPending()
		data, _ := json.Marshal(list)
		_, _ = conn.Write(append(data, '\n'))

	case "APPROVE":
		targetID := ""
		if len(parts) > 1 {
			targetID = strings.TrimSpace(parts[1])
		}
		if targetID == "" || targetID == "--last" {
			last := m.GetLastPending()
			if last != nil {
				targetID = last.ID
			}
		}
		if targetID == "" {
			_, _ = conn.Write([]byte("ERROR: No pending request found\n"))
			return
		}
		if err := m.Resolve(targetID, true); err != nil {
			_, _ = conn.Write([]byte(fmt.Sprintf("ERROR: %s\n", err.Error())))
		} else {
			_, _ = conn.Write([]byte(fmt.Sprintf("OK: Approved %s\n", targetID)))
		}

	case "DENY":
		targetID := ""
		if len(parts) > 1 {
			targetID = strings.TrimSpace(parts[1])
		}
		if targetID == "" || targetID == "--last" {
			last := m.GetLastPending()
			if last != nil {
				targetID = last.ID
			}
		}
		if targetID == "" {
			_, _ = conn.Write([]byte("ERROR: No pending request found\n"))
			return
		}
		if err := m.Resolve(targetID, false); err != nil {
			_, _ = conn.Write([]byte(fmt.Sprintf("ERROR: %s\n", err.Error())))
		} else {
			_, _ = conn.Write([]byte(fmt.Sprintf("OK: Denied %s\n", targetID)))
		}

	default:
		_, _ = conn.Write([]byte("ERROR: Unknown command\n"))
	}
}

// SendControlCommand communicates with active SecretHarbor control socket(s) from a secondary CLI.
// Multiplexes across multiple active sessions and allows targeting session/PID (BUG-023).
func SendControlCommand(command string) (string, error) {
	sockDir, err := getSecretHarborDir()
	if err != nil {
		return "", err
	}

	var targetSockPaths []string
	if targetPID := os.Getenv("SECRETHARBOR_PID"); targetPID != "" {
		targetSockPaths = append(targetSockPaths, filepath.Join(sockDir, fmt.Sprintf("control.%s.sock", targetPID)))
	}

	mainSock := filepath.Join(sockDir, "control.sock")
	targetSockPaths = append(targetSockPaths, mainSock)

	// Discover all other session-specific sockets in sockDir
	if entries, err := os.ReadDir(sockDir); err == nil {
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, "control.") && strings.HasSuffix(name, ".sock") && name != "control.sock" {
				p := filepath.Join(sockDir, name)
				found := false
				for _, existing := range targetSockPaths {
					if existing == p {
						found = true
						break
					}
				}
				if !found {
					targetSockPaths = append(targetSockPaths, p)
				}
			}
		}
	}

	sendToSock := func(sockPath string) (string, error) {
		conn, err := net.DialTimeout("unix", sockPath, 300*time.Millisecond)
		if err != nil {
			return "", err
		}
		defer conn.Close()

		token := readTokenForSocket(sockDir, sockPath)
		if token != "" {
			if _, err := fmt.Fprintf(conn, "AUTH %s\n", token); err != nil {
				return "", err
			}
		}
		if _, err := fmt.Fprintf(conn, "%s\n", command); err != nil {
			return "", err
		}

		reader := bufio.NewReader(conn)
		resp, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(resp), nil
	}

	// For LIST, query and merge results from all active sessions
	if strings.ToUpper(strings.TrimSpace(command)) == "LIST" {
		var allRequests []*Request
		foundAny := false
		for _, sp := range targetSockPaths {
			resp, err := sendToSock(sp)
			if err != nil {
				continue
			}
			foundAny = true
			var list []*Request
			if err := json.Unmarshal([]byte(resp), &list); err == nil {
				allRequests = append(allRequests, list...)
			}
		}
		if !foundAny {
			return "", fmt.Errorf("no active SecretHarbor session running")
		}
		data, _ := json.Marshal(allRequests)
		return string(data), nil
	}

	// For APPROVE or DENY, try each socket until request is resolved
	var lastErr error
	var lastResp string
	for _, sp := range targetSockPaths {
		resp, err := sendToSock(sp)
		if err != nil {
			lastErr = err
			continue
		}
		lastResp = resp
		if strings.HasPrefix(resp, "OK:") {
			return resp, nil
		}
		// If error is not "No pending request found" or "not found", return immediately
		if !strings.Contains(resp, "not found") && !strings.Contains(resp, "No pending request") {
			return resp, nil
		}
	}

	if lastResp != "" {
		return lastResp, nil
	}
	if lastErr != nil {
		return "", fmt.Errorf("no active SecretHarbor session running (%w)", lastErr)
	}
	return "", fmt.Errorf("no active SecretHarbor session running")
}

func readTokenForSocket(sockDir, sockPath string) string {
	base := filepath.Base(sockPath)
	if strings.HasPrefix(base, "control.") && strings.HasSuffix(base, ".sock") {
		tokName := strings.Replace(base, "control.", "auth.", 1)
		tokName = strings.Replace(tokName, ".sock", ".token", 1)
		if data, err := os.ReadFile(filepath.Join(sockDir, tokName)); err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	if data, err := os.ReadFile(filepath.Join(sockDir, "auth.token")); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}
