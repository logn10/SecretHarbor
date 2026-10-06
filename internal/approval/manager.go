package approval

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// RequestStatus represents the state of an escalation request.
type RequestStatus string

const (
	StatusPending  RequestStatus = "pending"
	StatusApproved RequestStatus = "approved"
	StatusDenied   RequestStatus = "denied"
	StatusExpired  RequestStatus = "expired"
)

// Request represents a pending capability escalation or unsandboxed execution request.
type Request struct {
	ID         string        `json:"id"`
	AgentName  string        `json:"agent_name"`
	PID        int           `json:"pid"`
	Capability string        `json:"capability"`
	Details    string        `json:"details"`
	CreatedAt  time.Time     `json:"created_at"`
	ExpiresAt  time.Time     `json:"expires_at"`
	Status     RequestStatus `json:"status"`

	responseChan chan bool
}

// Manager coordinates escalation requests, process pausing, and multi-channel notifications.
type Manager struct {
	mu          sync.Mutex
	requests    map[string]*Request
	agentPIDs   map[int]bool
	lastReqID   string
	socketPath  string
	symlinkPath string
	tokenPath   string
	authToken   string
	listener    net.Listener
	stopChan    chan struct{}
}

// GlobalManager is the active approval coordinator instance.
var GlobalManager = NewManager()

// NewManager creates a new Approval Manager.
func NewManager() *Manager {
	return &Manager{
		requests:  make(map[string]*Request),
		agentPIDs: make(map[int]bool),
		stopChan:  make(chan struct{}),
	}
}

func getSecretHarborDir() (string, error) {
	sockDir := os.Getenv("SECRETHARBOR_DIR")
	if sockDir != "" {
		return sockDir, os.MkdirAll(sockDir, 0700)
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		sockDir = filepath.Join(home, ".secretharbor")
		return sockDir, os.MkdirAll(sockDir, 0700)
	}
	// Never fall back to shared world-writable /tmp without creating a secure 0700 private user directory (BUG-021)
	userDir := filepath.Join(os.TempDir(), fmt.Sprintf(".secretharbor-%d", os.Getuid()))
	if err := os.MkdirAll(userDir, 0700); err != nil {
		return "", err
	}
	_ = os.Chmod(userDir, 0700)
	return userDir, nil
}

func generateAuthToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// shortSocketDir returns a short 0700 directory for control sockets. Unix socket
// paths are limited to ~104 bytes on macOS, which long home directories can exceed.
func shortSocketDir() string {
	user := os.Getenv("USER")
	if user == "" {
		user = fmt.Sprintf("uid-%d", os.Getuid())
	}
	dir := filepath.Join(os.TempDir(), fmt.Sprintf(".shb-%s", user))
	_ = os.MkdirAll(dir, 0700)
	_ = os.Chmod(dir, 0700)
	return dir
}

// StartControlSocket binds socket for secondary CLI communication.
func (m *Manager) StartControlSocket() error {
	sockDir, err := getSecretHarborDir()
	if err != nil {
		return err
	}

	m.authToken = generateAuthToken()
	pid := os.Getpid()

	// Write secret authorization token generated at manager start mode 0600 (BUG-003)
	sessionTokenPath := filepath.Join(sockDir, fmt.Sprintf("auth.%d.token", pid))
	if err := os.WriteFile(sessionTokenPath, []byte(m.authToken), 0600); err != nil {
		return err
	}
	m.tokenPath = sessionTokenPath

	// Bind the real socket at a short path; discoverability symlinks live in sockDir.
	shortDir := shortSocketDir()
	sessionSockPath := filepath.Join(shortDir, fmt.Sprintf("c-%d.sock", pid))
	_ = os.Remove(sessionSockPath)
	m.socketPath = sessionSockPath

	l, err := net.Listen("unix", m.socketPath)
	if err != nil {
		_ = os.Remove(m.tokenPath)
		return err
	}
	m.listener = l
	_ = os.Chmod(m.socketPath, 0600) // Ensure strictly accessible by human user only

	// Symlink management for control.sock / control.<pid>.sock and auth.token (BUG-023)
	linkSockPath := filepath.Join(sockDir, fmt.Sprintf("control.%d.sock", pid))
	mainSockPath := filepath.Join(sockDir, "control.sock")
	mainTokenPath := filepath.Join(sockDir, "auth.token")
	_ = os.Remove(linkSockPath)
	_ = os.Symlink(sessionSockPath, linkSockPath)

	// Check if control.sock is currently serving an active instance
	active := false
	if conn, err := net.DialTimeout("unix", mainSockPath, 100*time.Millisecond); err == nil {
		_ = conn.Close()
		active = true
	}

	if !active {
		_ = os.Remove(mainSockPath)
		_ = os.Symlink(sessionSockPath, mainSockPath)
		m.symlinkPath = mainSockPath

		_ = os.Remove(mainTokenPath)
		_ = os.Symlink(filepath.Base(sessionTokenPath), mainTokenPath)
	}

	go m.serveSocket()
	return nil
}

// Stop closes the control socket and cleans up resources.
func (m *Manager) Stop() {
	if m.listener != nil {
		_ = m.listener.Close()
	}
	if m.socketPath != "" {
		_ = os.Remove(m.socketPath)
	}
	if m.tokenPath != "" {
		_ = os.Remove(m.tokenPath)
	}

	sockDir, err := getSecretHarborDir()
	if err == nil {
		linkSockPath := filepath.Join(sockDir, fmt.Sprintf("control.%d.sock", os.Getpid()))
		_ = os.Remove(linkSockPath)

		mainSockPath := filepath.Join(sockDir, "control.sock")
		if target, err := os.Readlink(mainSockPath); err == nil {
			if target == m.socketPath || target == filepath.Base(m.socketPath) {
				_ = os.Remove(mainSockPath)
				repointActiveSession(sockDir)
			}
		}
		mainTokenPath := filepath.Join(sockDir, "auth.token")
		if target, err := os.Readlink(mainTokenPath); err == nil {
			if target == filepath.Base(m.tokenPath) || target == m.tokenPath {
				_ = os.Remove(mainTokenPath)
			}
		}
	}
}

func repointActiveSession(sockDir string) {
	entries, err := os.ReadDir(sockDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "control.") && strings.HasSuffix(name, ".sock") && name != "control.sock" {
			candidateSock := filepath.Join(sockDir, name)
			if conn, err := net.DialTimeout("unix", candidateSock, 100*time.Millisecond); err == nil {
				_ = conn.Close()
				mainSockPath := filepath.Join(sockDir, "control.sock")
				_ = os.Remove(mainSockPath)
				_ = os.Symlink(name, mainSockPath)

				tokenName := strings.Replace(name, "control.", "auth.", 1)
				tokenName = strings.Replace(tokenName, ".sock", ".token", 1)
				mainTokenPath := filepath.Join(sockDir, "auth.token")
				_ = os.Remove(mainTokenPath)
				_ = os.Symlink(tokenName, mainTokenPath)
				return
			}
		}
	}
}

// RequestApproval submits a new request, pauses the agent, and blocks until decision or timeout.
func (m *Manager) RequestApproval(agentName string, pid int, capability, details string, timeout time.Duration) (bool, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	reqID := generateRequestID()
	req := &Request{
		ID:           reqID,
		AgentName:    agentName,
		PID:          pid,
		Capability:   capability,
		Details:      details,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(timeout),
		Status:       StatusPending,
		responseChan: make(chan bool, 1),
	}

	m.mu.Lock()
	m.requests[reqID] = req
	m.lastReqID = reqID
	if pid > 0 {
		m.agentPIDs[pid] = true
	}
	m.mu.Unlock()

	// Prune resolved requests from memory map when RequestApproval completes (BUG-054)
	defer func() {
		m.mu.Lock()
		delete(m.requests, reqID)
		m.mu.Unlock()
	}()

	// 1. Pause the entire agent process tree (process group) to prevent speculative actions or simulated input
	if pid > 0 && pid != os.Getpid() {
		pauseProcess(pid)
	}

	// Always resume agent process tree on return
	defer func() {
		if pid > 0 && pid != os.Getpid() {
			resumeProcess(pid)
		}
	}()

	// 2. Dispatch out-of-band notification asynchronously
	go func() {
		approved, err := PromptOSDialog(req)
		if err == nil {
			if approved {
				_ = m.Resolve(reqID, true)
			} else {
				_ = m.Resolve(reqID, false)
			}
		}
	}()

	// 3. Await decision or fail-closed timeout
	select {
	case approved := <-req.responseChan:
		return approved, nil
	case <-time.After(timeout):
		m.mu.Lock()
		if req.Status == StatusPending {
			req.Status = StatusExpired
		}
		m.mu.Unlock()
		return false, errors.New("approval request timed out (defaulted to DENY)")
	}
}

// Resolve marks a request as approved or denied and unblocks the waiting caller.
func (m *Manager) Resolve(reqID string, approved bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, exists := m.requests[reqID]
	if !exists {
		return fmt.Errorf("request %s not found", reqID)
	}

	if req.Status != StatusPending {
		return fmt.Errorf("request %s is already %s", reqID, req.Status)
	}

	if approved {
		req.Status = StatusApproved
	} else {
		req.Status = StatusDenied
	}

	select {
	case req.responseChan <- approved:
	default:
	}

	return nil
}

// ListPending returns all currently pending requests.
func (m *Manager) ListPending() []*Request {
	m.mu.Lock()
	defer m.mu.Unlock()

	var list []*Request
	now := time.Now()
	for _, req := range m.requests {
		if req.Status == StatusPending && now.Before(req.ExpiresAt) {
			list = append(list, req)
		}
	}
	return list
}

// GetLastPending returns the most recently submitted pending request.
func (m *Manager) GetLastPending() *Request {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.lastReqID == "" {
		return nil
	}
	req := m.requests[m.lastReqID]
	if req != nil && req.Status == StatusPending && time.Now().Before(req.ExpiresAt) {
		return req
	}
	return nil
}

func (m *Manager) isCallerUnauthorized(callerPID int) bool {
	if callerPID <= 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Reject the agent process itself and any of its recorded descendants, regardless
	// of whether a request is currently pending (BUG-003).
	for pid := range m.agentPIDs {
		if isDescendantOf(callerPID, pid) {
			return true
		}
	}
	for _, req := range m.requests {
		if req.PID > 0 && isDescendantOf(callerPID, req.PID) {
			return true
		}
	}
	return false
}

func generateRequestID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("req_%s", hex.EncodeToString(b))
}
