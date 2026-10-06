package cli_test

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/secretharbor/secretharbor/internal/cli"
)

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestDetermineProgName(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"/usr/local/bin/shb", "version"}
	if name := cli.DetermineProgName("secretharbor"); name != "shb" {
		t.Errorf("expected shb, got %s", name)
	}

	os.Args = []string{"/usr/local/bin/secretharbor", "version"}
	if name := cli.DetermineProgName("shb"); name != "secretharbor" {
		t.Errorf("expected secretharbor, got %s", name)
	}

	os.Args = []string{"something_else", "version"}
	if name := cli.DetermineProgName("shb"); name != "shb" {
		t.Errorf("expected default shb, got %s", name)
	}
}

func TestCliHelpBothNames(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	// Test shb help
	os.Args = []string{"shb", "help"}
	outShb := captureStdout(func() {
		code := cli.Execute("shb")
		if code != 0 {
			t.Errorf("expected code 0 for shb help, got %d", code)
		}
	})

	if !bytes.Contains([]byte(outShb), []byte("shb <command> [arguments]")) {
		t.Errorf("expected shb usage in help output")
	}
	if !bytes.Contains([]byte(outShb), []byte("alias: secretharbor")) {
		t.Errorf("expected secretharbor alias in help output")
	}

	// Test secretharbor help
	os.Args = []string{"secretharbor", "help"}
	outSec := captureStdout(func() {
		code := cli.Execute("secretharbor")
		if code != 0 {
			t.Errorf("expected code 0 for secretharbor help, got %d", code)
		}
	})

	if !bytes.Contains([]byte(outSec), []byte("secretharbor <command> [arguments]")) {
		t.Errorf("expected secretharbor usage in help output")
	}
	if !bytes.Contains([]byte(outSec), []byte("alias: shb")) {
		t.Errorf("expected shb alias in help output")
	}
}

func TestCliVersionBothNames(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	os.Args = []string{"shb", "version"}
	outShb := captureStdout(func() {
		code := cli.Execute("shb")
		if code != 0 {
			t.Errorf("expected code 0 for shb version, got %d", code)
		}
	})
	expectedBanner := "SecretHarbor v" + cli.Version
	if !bytes.Contains([]byte(outShb), []byte(expectedBanner)) {
		t.Errorf("expected version banner %s, got: %s", expectedBanner, outShb)
	}
	if !bytes.Contains([]byte(outShb), []byte("[shb]")) {
		t.Errorf("expected [shb] tag, got: %s", outShb)
	}

	os.Args = []string{"secretharbor", "version"}
	outSec := captureStdout(func() {
		code := cli.Execute("secretharbor")
		if code != 0 {
			t.Errorf("expected code 0 for secretharbor version, got %d", code)
		}
	})
	if !bytes.Contains([]byte(outSec), []byte(expectedBanner)) {
		t.Errorf("expected version banner %s, got: %s", expectedBanner, outSec)
	}
	if !bytes.Contains([]byte(outSec), []byte("[secretharbor]")) {
		t.Errorf("expected [secretharbor] tag, got: %s", outSec)
	}
}

func TestCliSessionsAndStop(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	t.Setenv("SECRETHARBOR_DIR", t.TempDir())

	// Test sessions when empty
	os.Args = []string{"shb", "sessions"}
	outSess := captureStdout(func() {
		code := cli.Execute("shb")
		if code != 0 {
			t.Errorf("expected code 0 for empty sessions, got %d", code)
		}
	})
	if !bytes.Contains([]byte(outSess), []byte("No active SecretHarbor sessions")) {
		t.Errorf("expected no active sessions notice, got: %s", outSess)
	}

	// Test stop when empty
	os.Args = []string{"shb", "stop"}
	outStop := captureStdout(func() {
		code := cli.Execute("shb")
		if code != 0 {
			t.Errorf("expected code 0 for empty stop, got %d", code)
		}
	})
	if !bytes.Contains([]byte(outStop), []byte("No active SecretHarbor sessions found")) {
		t.Errorf("expected no active sessions notice, got: %s", outStop)
	}
}

func TestCliGuardOnOff(t *testing.T) {
	origArgs := os.Args
	defer func() { os.Args = origArgs }()

	tempDir, err := os.MkdirTemp("", "secretharbor-guard-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	origWd, _ := os.Getwd()
	_ = os.Chdir(tempDir)
	defer func() { _ = os.Chdir(origWd) }()

	// Init policy
	os.Args = []string{"shb", "init"}
	_ = cli.Execute("shb")

	// Guard off with --yes
	os.Args = []string{"shb", "guard", "off", "--yes"}
	outOff := captureStdout(func() {
		code := cli.Execute("shb")
		if code != 0 {
			t.Errorf("expected code 0 for guard off, got %d", code)
		}
	})
	if !bytes.Contains([]byte(outOff), []byte("turned OFF")) {
		t.Errorf("expected guard turned off message, got: %s", outOff)
	}

	// Guard on
	os.Args = []string{"shb", "guard", "on"}
	outOn := captureStdout(func() {
		code := cli.Execute("shb")
		if code != 0 {
			t.Errorf("expected code 0 for guard on, got %d", code)
		}
	})
	if !bytes.Contains([]byte(outOn), []byte("guard is now ON")) {
		t.Errorf("expected guard turned on message, got: %s", outOn)
	}
}
