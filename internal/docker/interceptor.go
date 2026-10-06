package docker

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/secretharbor/secretharbor/internal/approval"
)

// DefaultApprovalLease is the default validity duration for an approved Docker capability escalation.
const DefaultApprovalLease = 10 * time.Minute

// Interceptor provides capability-gated, out-of-band approved proxying to the Docker daemon.
type Interceptor struct {
	agentName      string
	realSocketPath string
	proxyPath      string
	secureDir      string
	listener       net.Listener
	pidMu          sync.RWMutex
	pid            int
	leaseDuration  time.Duration
	approvedUntil  atomic.Int64 // Unix nanoseconds
	closed         atomic.Bool
	stopChan       chan struct{}
	wg             sync.WaitGroup
	connMu         sync.Mutex
	activeConns    map[net.Conn]struct{}
	dialUpstream   func() (net.Conn, error)
}

// FindHostDockerSocket locates the host's actual Docker or Podman daemon Unix domain socket.
// Checks os.ModeSocket instead of regular files and returns an error if not found (BUG-054).
func FindHostDockerSocket() (string, error) {
	candidates := []string{
		"/var/run/docker.sock",
		"/run/podman/podman.sock",
	}

	home, _ := os.UserHomeDir()
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".docker/run/docker.sock"),
			filepath.Join(home, ".podman/podman.sock"),
			filepath.Join(home, ".colima/default/docker.sock"),
		)
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return c, nil
		}
	}
	return "", fmt.Errorf("no host Docker/Podman socket found in standard candidate paths")
}

// StartInterceptor starts an ephemeral Unix domain proxy socket that intercepts Docker daemon access
// and gates connections behind human approval.
func StartInterceptor(agentName string, realSocketPath string) (*Interceptor, error) {
	if realSocketPath == "" {
		var err error
		realSocketPath, err = FindHostDockerSocket()
		if err != nil {
			return nil, fmt.Errorf("failed to locate host Docker socket: %w", err)
		}
	}

	tmpDir := os.Getenv("SECRETHARBOR_TMPDIR")
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}

	// Create socket in secure directory with chmod 0700 (BUG-033)
	secureDir, err := os.MkdirTemp(tmpDir, fmt.Sprintf("shb-docker-%d-*", os.Getpid()))
	if err != nil {
		return nil, fmt.Errorf("failed to create secure directory for Docker interceptor: %w", err)
	}
	_ = os.Chmod(secureDir, 0700)

	proxyPath := filepath.Join(secureDir, fmt.Sprintf("shb-d-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%10000))
	_ = os.Remove(proxyPath)

	listener, err := net.Listen("unix", proxyPath)
	if err != nil {
		_ = os.RemoveAll(secureDir)
		return nil, fmt.Errorf("failed to bind Docker capability interceptor socket at %s: %w", proxyPath, err)
	}
	// Chmod socket strictly to 0600 (BUG-033)
	_ = os.Chmod(proxyPath, 0600)

	interceptor := &Interceptor{
		agentName:      agentName,
		realSocketPath: realSocketPath,
		proxyPath:      proxyPath,
		secureDir:      secureDir,
		listener:       listener,
		stopChan:       make(chan struct{}),
		activeConns:    make(map[net.Conn]struct{}),
	}
	interceptor.dialUpstream = func() (net.Conn, error) {
		return net.Dial("unix", interceptor.realSocketPath)
	}

	interceptor.wg.Add(1)
	go interceptor.acceptLoop()

	return interceptor, nil
}

// NewInterceptor creates an in-memory Interceptor instance without binding a filesystem socket.
func NewInterceptor(agentName string) *Interceptor {
	return &Interceptor{
		agentName:   agentName,
		stopChan:    make(chan struct{}),
		activeConns: make(map[net.Conn]struct{}),
	}
}

// SetUpstreamDialer configures a custom dialer function for upstream connections.
func (i *Interceptor) SetUpstreamDialer(dialer func() (net.Conn, error)) {
	i.dialUpstream = dialer
}

// SocketPath returns the ephemeral proxy socket path to set in DOCKER_HOST.
func (i *Interceptor) SocketPath() string {
	return i.proxyPath
}

// SetPID associates the sandboxed process PID with the interceptor for process-suspension approval.
// Synchronized with RWMutex (BUG-033).
func (i *Interceptor) SetPID(pid int) {
	i.pidMu.Lock()
	defer i.pidMu.Unlock()
	i.pid = pid
}

// PID returns the associated process PID with thread safety (BUG-033).
func (i *Interceptor) PID() int {
	i.pidMu.RLock()
	defer i.pidMu.RUnlock()
	return i.pid
}

// SetLeaseDuration overrides the default temporary lease duration.
func (i *Interceptor) SetLeaseDuration(d time.Duration) {
	i.leaseDuration = d
}

// IsApproved reports whether human approval is currently active and within its lease.
func (i *Interceptor) IsApproved() bool {
	return time.Now().UnixNano() < i.approvedUntil.Load()
}

// LeaseRemaining returns the remaining duration of the active approval lease.
func (i *Interceptor) LeaseRemaining() time.Duration {
	until := i.approvedUntil.Load()
	if until == 0 {
		return 0
	}
	remaining := time.Until(time.Unix(0, until))
	if remaining < 0 {
		return 0
	}
	return remaining
}

func (i *Interceptor) trackConn(c net.Conn, add bool) {
	if i == nil || c == nil {
		return
	}
	i.connMu.Lock()
	defer i.connMu.Unlock()
	if i.activeConns == nil {
		i.activeConns = make(map[net.Conn]struct{})
	}
	if add {
		i.activeConns[c] = struct{}{}
	} else {
		delete(i.activeConns, c)
	}
}

func (i *Interceptor) acceptLoop() {
	defer i.wg.Done()

	for {
		clientConn, err := i.listener.Accept()
		if err != nil {
			select {
			case <-i.stopChan:
				return
			default:
				if i.closed.Load() {
					return
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
		}

		if i.closed.Load() {
			_ = clientConn.Close()
			return
		}

		i.wg.Add(1)
		go func(c net.Conn) {
			defer i.wg.Done()
			i.HandleConnection(c)
		}(clientConn)
	}
}

// isDangerousEndpoint identifies high-risk Docker API calls that should not be given blanket approval (BUG-033).
func isDangerousEndpoint(method, path string) bool {
	path = strings.ToLower(path)
	if strings.Contains(path, "/system/prune") ||
		strings.Contains(path, "/swarm") ||
		strings.Contains(path, "/secrets") {
		return true
	}
	if method == http.MethodDelete && (strings.Contains(path, "/images") || strings.Contains(path, "/volumes")) {
		return true
	}
	return false
}

// isPerCommandCapabilityRequired reports if an endpoint requires per-command human approval (BUG-033).
func isPerCommandCapabilityRequired(method, path string) (bool, string) {
	path = strings.ToLower(path)
	if strings.Contains(path, "/containers/create") {
		return true, "docker:create"
	}
	if strings.Contains(path, "/exec") {
		return true, "docker:exec"
	}
	return false, ""
}

// HandleConnection processes an incoming client connection through the capability approval gate and upstream proxy.
func (i *Interceptor) HandleConnection(clientConn net.Conn) {
	i.trackConn(clientConn, true)
	defer func() {
		i.trackConn(clientConn, false)
		_ = clientConn.Close()
	}()

	if i.closed.Load() {
		return
	}

	// Read initial request to filter endpoints and determine required capability (BUG-033)
	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	// 1. Block dangerous / administrative endpoints outright
	if isDangerousEndpoint(req.Method, req.URL.Path) {
		resp := "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nSecretHarbor: Docker endpoint forbidden by capability policy\n"
		_, _ = clientConn.Write([]byte(resp))
		return
	}

	// 2. Check per-command capability requirement vs general lease (BUG-033)
	requiresPerCmd, perCmdCap := isPerCommandCapabilityRequired(req.Method, req.URL.Path)

	pid := i.PID()

	if requiresPerCmd {
		// High-risk command requires dedicated capability escalation
		type approvalResult struct {
			approved bool
			err      error
		}
		resChan := make(chan approvalResult, 1)
		go func() {
			approved, err := approval.GlobalManager.RequestApproval(
				i.agentName,
				pid,
				perCmdCap,
				fmt.Sprintf("Agent requested privileged Docker action: %s %s", req.Method, req.URL.Path),
				30*time.Second,
			)
			resChan <- approvalResult{approved: approved, err: err}
		}()

		select {
		case <-i.stopChan:
			return
		case res := <-resChan:
			if res.err != nil || !res.approved {
				resp := "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nSecretHarbor: Docker privileged action denied\n"
				_, _ = clientConn.Write([]byte(resp))
				return
			}
		}
	} else if !i.IsApproved() {
		// General Docker capability escalation
		type approvalResult struct {
			approved bool
			err      error
		}
		resChan := make(chan approvalResult, 1)
		go func() {
			approved, err := approval.GlobalManager.RequestApproval(
				i.agentName,
				pid,
				"ipc:docker",
				fmt.Sprintf("Agent requested access to Docker daemon socket (%s)", i.realSocketPath),
				30*time.Second,
			)
			resChan <- approvalResult{approved: approved, err: err}
		}()

		select {
		case <-i.stopChan:
			return
		case res := <-resChan:
			if res.err != nil || !res.approved {
				return
			}
		}

		lease := i.leaseDuration
		if lease <= 0 {
			lease = DefaultApprovalLease
		}
		i.approvedUntil.Store(time.Now().Add(lease).UnixNano())
	}

	if i.closed.Load() {
		return
	}

	dialer := i.dialUpstream
	if dialer == nil {
		dialer = func() (net.Conn, error) {
			return net.Dial("unix", i.realSocketPath)
		}
	}

	// Connect to real Docker socket
	upstreamConn, err := dialer()
	if err != nil {
		return
	}
	i.trackConn(upstreamConn, true)
	defer func() {
		i.trackConn(upstreamConn, false)
		_ = upstreamConn.Close()
	}()

	// Write intercepted request to upstream
	if err := req.Write(upstreamConn); err != nil {
		return
	}

	// Bidirectional proxy stream for the remainder of the connection
	closeBoth := func() {
		_ = clientConn.Close()
		_ = upstreamConn.Close()
	}

	done := make(chan struct{}, 2)

	go func() {
		_, _ = io.Copy(upstreamConn, reader)
		closeBoth()
		done <- struct{}{}
	}()

	go func() {
		_, _ = io.Copy(clientConn, upstreamConn)
		closeBoth()
		done <- struct{}{}
	}()

	<-done
	<-done
}

// Close terminates the listener, closes all active connections, and cleans up the ephemeral proxy socket file.
func (i *Interceptor) Close() error {
	if i.closed.Swap(true) {
		return nil
	}

	close(i.stopChan)
	var err error
	if i.listener != nil {
		err = i.listener.Close()
	}

	// Terminate all active connections immediately
	i.connMu.Lock()
	for c := range i.activeConns {
		_ = c.Close()
	}
	i.connMu.Unlock()

	i.wg.Wait()
	if i.proxyPath != "" {
		_ = os.Remove(i.proxyPath)
	}
	if i.secureDir != "" {
		_ = os.RemoveAll(i.secureDir)
	}
	return err
}
