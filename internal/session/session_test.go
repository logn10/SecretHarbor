package session_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/secretharbor/secretharbor/internal/session"
)

func TestSessionLifecycle(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secretharbor-session-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origDir := os.Getenv("SECRETHARBOR_DIR")
	os.Setenv("SECRETHARBOR_DIR", tempDir)
	defer func() {
		if origDir != "" {
			os.Setenv("SECRETHARBOR_DIR", origDir)
		} else {
			os.Unsetenv("SECRETHARBOR_DIR")
		}
	}()

	// Start a dummy sleep process
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep process: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	dummySandbox, _ := os.MkdirTemp("", "dummy-sandbox-*")

	// Register session
	sess, err := session.Register("claude", "sleep 10", "/tmp/my-project", cmd.Process.Pid, 0, dummySandbox)
	if err != nil {
		t.Fatalf("failed to register session: %v", err)
	}

	if sess.Agent != "Claude" {
		t.Errorf("expected Claude, got %s", sess.Agent)
	}
	if sess.Status != "RUNNING" {
		t.Errorf("expected RUNNING status, got %s", sess.Status)
	}

	// List sessions
	list, err := session.List()
	if err != nil {
		t.Fatalf("failed to list sessions: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 session, got %d", len(list))
	}
	if list[0].ID != sess.ID {
		t.Errorf("expected ID %s, got %s", sess.ID, list[0].ID)
	}

	// Lookup by ID
	found, err := session.Get(sess.ID)
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if found.ID != sess.ID {
		t.Errorf("expected ID %s, got %s", sess.ID, found.ID)
	}

	// Lookup by prefix
	prefix := sess.ID[:2]
	foundPrefix, err := session.Get(prefix)
	if err != nil {
		t.Fatalf("failed to get session by prefix %s: %v", prefix, err)
	}
	if foundPrefix.ID != sess.ID {
		t.Errorf("expected prefix match %s, got %s", sess.ID, foundPrefix.ID)
	}

	// Stop session
	if err := session.StopSession(sess); err != nil {
		t.Fatalf("failed to stop session: %v", err)
	}

	// Scratch directories are owned by the sandbox supervisor (synced and removed
	// during sandbox cleanup) or reclaimed by the age-based cleaner, not by session stop.
	if _, err := os.Stat(dummySandbox); err != nil {
		t.Errorf("sandbox scratch directory should still exist after stop (cleanup is deferred): %v", err)
	}
	_ = os.RemoveAll(dummySandbox)

	// Allow OS a brief moment to reap
	time.Sleep(100 * time.Millisecond)

	// List sessions should now be empty
	listAfter, err := session.List()
	if err != nil {
		t.Fatalf("failed to list sessions after stop: %v", err)
	}
	if len(listAfter) != 0 {
		t.Errorf("expected 0 sessions after stop, got %d", len(listAfter))
	}
}

func TestSessionStaleProcessPruning(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "secretharbor-stale-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origDir := os.Getenv("SECRETHARBOR_DIR")
	os.Setenv("SECRETHARBOR_DIR", tempDir)
	defer func() {
		if origDir != "" {
			os.Setenv("SECRETHARBOR_DIR", origDir)
		} else {
			os.Unsetenv("SECRETHARBOR_DIR")
		}
	}()

	// Register a session with a non-existent PID (9999999)
	sess, err := session.Register("codex", "codex", "/tmp/api", 9999999, 0, "")
	if err != nil {
		t.Fatalf("failed to register session: %v", err)
	}

	// Ensure the file exists
	sessPath := filepath.Join(tempDir, "sessions", sess.ID+".json")
	if _, err := os.Stat(sessPath); err != nil {
		t.Fatalf("expected session file to exist: %v", err)
	}

	// List() should detect the dead PID and prune it automatically
	list, err := session.List()
	if err != nil {
		t.Fatalf("failed to list sessions: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 active sessions, got %d", len(list))
	}

	// File should have been removed
	if _, err := os.Stat(sessPath); !os.IsNotExist(err) {
		t.Errorf("expected stale session file to be removed")
	}
}

func TestSessionIDLengthAndEntropy(t *testing.T) {
	id := session.GenerateID()
	if len(id) != 32 { // 16 bytes hex = 32 chars
		t.Errorf("expected 32-character hex ID (16 bytes), got %d (%s)", len(id), id)
	}
}

func TestSessionIdentityValidation(t *testing.T) {
	sess := &session.Session{
		PID:              os.Getpid(),
		ProcessStartTime: "Non-matching-start-time-12345",
		ProcessName:      "non-matching-process-name-xyz",
	}
	if sess.ValidateIdentity() {
		t.Errorf("expected ValidateIdentity to fail for mismatched start time")
	}
}

func TestStopNeverRemovesProjectDirectory(t *testing.T) {
	t.Setenv("SECRETHARBOR_DIR", t.TempDir())

	projDir := filepath.Join(t.TempDir(), "myproject")
	if err := os.MkdirAll(projDir, 0700); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(projDir, ".env")
	if err := os.WriteFile(envPath, []byte("K=1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	// Simulate the historical bug: SandboxDir accidentally equals the project dir.
	sess, err := session.Register("claude", "sleep 10", projDir, cmd.Process.Pid, 0, projDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.StopSession(sess); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(envPath); err != nil {
		t.Fatalf("project directory must never be removed on stop: %v", err)
	}
}
