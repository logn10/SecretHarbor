package approval_test

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/secretharbor/secretharbor/internal/approval"
)

func TestApprovalApprove(t *testing.T) {
	mgr := approval.NewManager()

	done := make(chan bool)
	go func() {
		approved, err := mgr.RequestApproval("test-agent", 0, "unsandboxed_exec", "make test", 2*time.Second)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		done <- approved
	}()

	// Wait for request to register
	time.Sleep(50 * time.Millisecond)

	req := mgr.GetLastPending()
	if req == nil {
		t.Fatal("expected pending request, got nil")
	}
	if req.Capability != "unsandboxed_exec" {
		t.Errorf("unexpected capability: %s", req.Capability)
	}

	// Resolve as approved
	if err := mgr.Resolve(req.ID, true); err != nil {
		t.Fatalf("unexpected error resolving: %v", err)
	}

	select {
	case approved := <-done:
		if !approved {
			t.Errorf("expected request to be approved")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for approval response")
	}

	// Verify resolved request is pruned from memory (BUG-054)
	time.Sleep(50 * time.Millisecond)
	if pending := mgr.ListPending(); len(pending) != 0 {
		t.Errorf("expected 0 pending requests after resolution, got %d", len(pending))
	}
}

func TestApprovalDeny(t *testing.T) {
	mgr := approval.NewManager()

	done := make(chan bool)
	go func() {
		approved, err := mgr.RequestApproval("test-agent", 0, "network_access", "api.internal", 2*time.Second)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		done <- approved
	}()

	time.Sleep(50 * time.Millisecond)
	req := mgr.GetLastPending()
	if req == nil {
		t.Fatal("expected pending request, got nil")
	}

	// Resolve as denied
	if err := mgr.Resolve(req.ID, false); err != nil {
		t.Fatalf("unexpected error resolving: %v", err)
	}

	select {
	case approved := <-done:
		if approved {
			t.Errorf("expected request to be denied")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for denial response")
	}
}

func TestApprovalTimeoutFailClosed(t *testing.T) {
	mgr := approval.NewManager()

	// Short timeout: 100ms
	approved, err := mgr.RequestApproval("test-agent", 0, "unsandboxed_exec", "rm -rf", 100*time.Millisecond)
	if err == nil {
		t.Errorf("expected timeout error, got nil")
	}
	if approved {
		t.Errorf("timed out request must fail closed (deny), but got approved=true")
	}

	// Verify request is pruned on timeout (BUG-054)
	time.Sleep(50 * time.Millisecond)
	if pending := mgr.ListPending(); len(pending) != 0 {
		t.Errorf("expected 0 pending requests after timeout, got %d", len(pending))
	}
}

func TestControlSocketAuthAndSelfApprovalRejection(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "shb-approval-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origDir := os.Getenv("SECRETHARBOR_DIR")
	os.Setenv("SECRETHARBOR_DIR", tmpDir)
	defer func() {
		if origDir != "" {
			os.Setenv("SECRETHARBOR_DIR", origDir)
		} else {
			os.Unsetenv("SECRETHARBOR_DIR")
		}
	}()

	mgr := approval.NewManager()
	if err := mgr.StartControlSocket(); err != nil {
		t.Fatalf("failed to start control socket: %v", err)
	}
	defer mgr.Stop()

	// 1. Submit request with PID = current process PID to test self-approval rejection
	myPID := os.Getpid()
	go func() {
		_, _ = mgr.RequestApproval("self-agent", myPID, "unsandboxed_exec", "danger", 3*time.Second)
	}()

	time.Sleep(50 * time.Millisecond)
	req := mgr.GetLastPending()
	if req == nil {
		t.Fatal("expected pending request")
	}

	// 2. Connecting from current process (PID == myPID) must be rejected because caller PID is the sandboxed PID
	sockPath := filepath.Join(tmpDir, "control.sock")
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to dial control socket: %v", err)
	}
	defer conn.Close()

	// Read token
	tokenBytes, err := os.ReadFile(filepath.Join(tmpDir, "auth.token"))
	if err != nil {
		t.Fatalf("expected auth.token to be generated: %v", err)
	}
	token := strings.TrimSpace(string(tokenBytes))

	_, _ = fmt.Fprintf(conn, "AUTH %s\nAPPROVE %s\n", token, req.ID)
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	resp := string(buf[:n])

	if !strings.Contains(resp, "Unauthorized caller PID") {
		t.Errorf("expected rejection of sandboxed agent self-approval, got: %s", resp)
	}
}

func TestMultiSessionControlSocketRouting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "shb-multisess-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	origDir := os.Getenv("SECRETHARBOR_DIR")
	os.Setenv("SECRETHARBOR_DIR", tmpDir)
	defer func() {
		if origDir != "" {
			os.Setenv("SECRETHARBOR_DIR", origDir)
		} else {
			os.Unsetenv("SECRETHARBOR_DIR")
		}
	}()

	mgr1 := approval.NewManager()
	if err := mgr1.StartControlSocket(); err != nil {
		t.Fatalf("failed to start mgr1 control socket: %v", err)
	}
	defer mgr1.Stop()

	// Simulate second session with distinct PID in socket name
	sock2Path := filepath.Join(tmpDir, "control.99999.sock")
	tok2Path := filepath.Join(tmpDir, "auth.99999.token")
	_ = os.WriteFile(tok2Path, []byte("token99999"), 0600)

	l2, err := net.Listen("unix", sock2Path)
	if err != nil {
		t.Fatalf("failed to listen on sock2: %v", err)
	}
	defer l2.Close()
	defer os.Remove(sock2Path)
	defer os.Remove(tok2Path)

	go func() {
		conn, err := l2.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			if strings.Contains(line, "LIST") {
				_, _ = conn.Write([]byte(`[{"id":"req_99999","agent_name":"agent2","status":"pending"}]` + "\n"))
				return
			}
		}
	}()

	// Test SendControlCommand LIST multiplexing
	resp, err := approval.SendControlCommand("LIST")
	if err != nil {
		t.Fatalf("SendControlCommand failed: %v", err)
	}
	if !strings.Contains(resp, "req_99999") {
		t.Errorf("expected LIST to include session 2 request, got: %s", resp)
	}
}
