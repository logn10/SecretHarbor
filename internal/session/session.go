package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Session represents an active SecretHarbor-managed agent session.
type Session struct {
	ID               string    `json:"id"`
	Agent            string    `json:"agent"`
	Command          string    `json:"command"`
	Project          string    `json:"project"`
	ProjectDir       string    `json:"project_dir"`
	PID              int       `json:"pid"`
	PGID             int       `json:"pgid"`
	Status           string    `json:"status"` // "RUNNING", "STOPPED"
	StartedAt        time.Time `json:"started_at"`
	ProcessName      string    `json:"process_name,omitempty"`
	ProcessStartTime string    `json:"process_start_time,omitempty"`
	SandboxDir       string    `json:"sandbox_dir,omitempty"`
}

// GetSessionsDir returns the directory where session files are stored.
func GetSessionsDir() string {
	dir := os.Getenv("SECRETHARBOR_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			home = os.Getenv("HOME")
		}
		if home == "" {
			// BUG-021: Do not use shared /tmp without creating a secure 0700 private user directory
			tmpBase := os.TempDir()
			user := os.Getenv("USER")
			if user == "" {
				user = fmt.Sprintf("uid-%d", os.Getuid())
			}
			privateDir := filepath.Join(tmpBase, fmt.Sprintf(".secretharbor-%s", user))
			_ = os.MkdirAll(privateDir, 0700)
			home = privateDir
		}
		dir = filepath.Join(home, ".secretharbor")
	}
	sessDir := filepath.Join(dir, "sessions")
	_ = os.MkdirAll(sessDir, 0700)
	return sessDir
}

// GenerateID produces a 16-byte cryptographically secure hex session ID.
func GenerateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x%016x", time.Now().UnixNano(), os.Getpid())
	}
	return hex.EncodeToString(b)
}

// FormatAgentName capitalizes known agents for display.
func FormatAgentName(agent string) string {
	switch strings.ToLower(agent) {
	case "claude":
		return "Claude"
	case "codex":
		return "Codex"
	case "gemini":
		return "Gemini"
	case "cursor":
		return "Cursor"
	case "--", "generic", "":
		return "Generic"
	default:
		return strings.ToUpper(agent[:1]) + agent[1:]
	}
}

// Register creates and persists a new session file using atomic file write.
func Register(agent, command, projectDir string, pid, pgid int, sandboxDir string) (*Session, error) {
	sessDir := GetSessionsDir()
	if err := os.MkdirAll(sessDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create sessions directory: %w", err)
	}

	absDir, err := filepath.Abs(projectDir)
	if err != nil {
		absDir = projectDir
	}
	projName := filepath.Base(absDir)
	if projName == "/" || projName == "." {
		projName = "root"
	}

	id := GenerateID()
	startTime, procName, _ := getProcessIdentityOS(pid)

	sess := &Session{
		ID:               id,
		Agent:            FormatAgentName(agent),
		Command:          command,
		Project:          projName,
		ProjectDir:       absDir,
		PID:              pid,
		PGID:             pgid,
		Status:           "RUNNING",
		StartedAt:        time.Now(),
		ProcessName:      procName,
		ProcessStartTime: startTime,
		SandboxDir:       sandboxDir,
	}

	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return nil, err
	}

	sessFile := filepath.Join(sessDir, fmt.Sprintf("%s.json", id))
	// Atomic file creation: temp file + sync + rename
	tmpFile, err := os.CreateTemp(sessDir, fmt.Sprintf(".tmp-%s-*", id))
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary session file: %w", err)
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return nil, err
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return nil, err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return nil, err
	}
	if err := tmpFile.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, sessFile); err != nil {
		return nil, fmt.Errorf("failed to write session file: %w", err)
	}

	return sess, nil
}

// Unregister deletes the session file from disk.
func Unregister(id string) error {
	sessFile := filepath.Join(GetSessionsDir(), fmt.Sprintf("%s.json", id))
	_ = os.Remove(sessFile)
	return nil
}

// IsProcessAlive checks if a process with the given PID is currently running.
func IsProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return isProcessAliveOS(pid)
}

// ValidateIdentity checks if the process currently running at PID matches recorded session identity.
func (s *Session) ValidateIdentity() bool {
	if s == nil || s.PID <= 0 {
		return false
	}
	if !IsProcessAlive(s.PID) {
		return false
	}
	if s.ProcessStartTime == "" && s.ProcessName == "" {
		return true
	}
	currentStart, currentName, err := getProcessIdentityOS(s.PID)
	if err != nil {
		return true
	}
	if s.ProcessStartTime != "" && currentStart != "" && currentStart != s.ProcessStartTime {
		return false // PID reuse detected!
	}
	// Process name is only used as a fallback when no start time is available:
	// launchers such as sandbox-exec exec(2) the target, changing comm while keeping the PID.
	if s.ProcessStartTime == "" && s.ProcessName != "" && currentName != "" {
		baseExpected := filepath.Base(s.ProcessName)
		baseCurrent := filepath.Base(currentName)
		if baseExpected != baseCurrent && !strings.Contains(currentName, baseExpected) {
			return false // PID reuse by different process!
		}
	}
	return true
}

// List returns all active running sessions, automatically pruning dead/stale sessions.
// Partial or incomplete file reads do not cause active sessions to be deleted.
func List() ([]*Session, error) {
	sessDir := GetSessionsDir()
	entries, err := os.ReadDir(sessDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var active []*Session
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}

		filePath := filepath.Join(sessDir, e.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		var sess Session
		if err := json.Unmarshal(data, &sess); err != nil {
			// BUG-041: Do not delete active sessions on partial read error
			continue
		}

		// Prune dead or PID-reused sessions (BUG-018)
		if !IsProcessAlive(sess.PID) || !sess.ValidateIdentity() {
			_ = os.Remove(filePath)
			if sess.SandboxDir != "" {
				_ = os.RemoveAll(sess.SandboxDir)
			}
			continue
		}

		active = append(active, &sess)
	}

	sort.Slice(active, func(i, j int) bool {
		return active[i].StartedAt.Before(active[j].StartedAt)
	})

	return active, nil
}

// Get finds a session by exact ID or prefix.
func Get(idOrPrefix string) (*Session, error) {
	sessions, err := List()
	if err != nil {
		return nil, err
	}

	idOrPrefix = strings.ToLower(strings.TrimSpace(idOrPrefix))
	var matches []*Session

	for _, s := range sessions {
		if strings.ToLower(s.ID) == idOrPrefix {
			return s, nil
		}
		if strings.HasPrefix(strings.ToLower(s.ID), idOrPrefix) {
			matches = append(matches, s)
		}
	}

	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("ambiguous session ID prefix %q matches %d sessions", idOrPrefix, len(matches))
	}

	// Fallback: match by agent name or command binary
	for _, s := range sessions {
		if strings.ToLower(s.Agent) == idOrPrefix || strings.ToLower(filepath.Base(s.Command)) == idOrPrefix {
			matches = append(matches, s)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("multiple active sessions for agent %q; specify session ID", idOrPrefix)
	}

	return nil, fmt.Errorf("session %q not found", idOrPrefix)
}

// GetForProject finds an active session for the specified project directory.
func GetForProject(projectDir string) (*Session, error) {
	absDir, err := filepath.Abs(projectDir)
	if err != nil {
		absDir = projectDir
	}

	sessions, err := List()
	if err != nil {
		return nil, err
	}

	for _, s := range sessions {
		if s.ProjectDir == absDir {
			return s, nil
		}
	}

	return nil, fmt.Errorf("no active SecretHarbor session for %s", absDir)
}

// Stop safely terminates a session process and all its children.
func (s *Session) Stop() error {
	if !IsProcessAlive(s.PID) {
		_ = Unregister(s.ID)
		return nil
	}

	// BUG-018: Revalidate identity before signaling to prevent killing unrelated processes after PID reuse
	if !s.ValidateIdentity() {
		_ = Unregister(s.ID)
		return nil
	}

	// Terminate the entire process tree (all helper/worker processes and root)
	KillProcessTree(s.PID)

	// Clean up temporary shadow workspace or scratch directories
	if s.SandboxDir != "" {
		_ = os.RemoveAll(s.SandboxDir)
	}

	// Remove session record
	_ = Unregister(s.ID)
	return nil
}

// StopSession cleanly terminates the agent process tree and removes temporary state.
func StopSession(s *Session) error {
	if s == nil {
		return nil
	}
	return s.Stop()
}

// KillProcessTree terminates rootPID and all of its descendant child processes.
func KillProcessTree(rootPID int) {
	if rootPID <= 0 {
		return
	}
	descendants := GetProcessDescendants(rootPID)
	killProcessTreeOS(rootPID, descendants)
}

// GetProcessDescendants returns all descendant PIDs under rootPID.
func GetProcessDescendants(rootPID int) []int {
	return getProcessDescendantsOS(rootPID)
}

// GetProcessIdentity returns the process start time and process name for the given PID.
func GetProcessIdentity(pid int) (startTime string, name string, err error) {
	return getProcessIdentityOS(pid)
}
