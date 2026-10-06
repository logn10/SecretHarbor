package cleaner_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/secretharbor/secretharbor/internal/cleaner"
)

func TestCleanOrphans(t *testing.T) {
	// 1. Create a dummy dead socket in /tmp with PID 9999999 (non-existent process)
	deadSock := filepath.Join("/tmp", fmt.Sprintf("shb-d-9999999-%d.sock", time.Now().UnixNano()%10000))
	if err := os.WriteFile(deadSock, []byte(""), 0600); err != nil {
		t.Fatalf("failed to create dummy socket: %v", err)
	}

	res := cleaner.CleanOrphans()
	if res.CleanedSockets == 0 {
		t.Errorf("expected at least 1 cleaned socket, got %d", res.CleanedSockets)
	}

	if _, err := os.Stat(deadSock); !os.IsNotExist(err) {
		t.Errorf("expected dummy dead socket to be removed")
	}
}
