package cli_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretharbor/secretharbor/internal/agents"
	"github.com/secretharbor/secretharbor/internal/cli"
)

func captureStdoutAndStderr(fn func()) (string, string) {
	oldOut := os.Stdout
	oldErr := os.Stderr

	rOut, wOut, _ := os.Pipe()
	rErr, wErr, _ := os.Pipe()

	os.Stdout = wOut
	os.Stderr = wErr

	fn()

	_ = wOut.Close()
	_ = wErr.Close()

	os.Stdout = oldOut
	os.Stderr = oldErr

	var bufOut, bufErr bytes.Buffer
	_, _ = io.Copy(&bufOut, rOut)
	_, _ = io.Copy(&bufErr, rErr)

	return bufOut.String(), bufErr.String()
}

func TestAdoptHelp(t *testing.T) {
	help := cli.RenderHelp("shb", "adopt")
	if !strings.Contains(help, "shb adopt") {
		t.Errorf("expected usage in adopt help, got:\n%s", help)
	}
	if !strings.Contains(help, "--yes") {
		t.Errorf("expected --yes option in adopt help, got:\n%s", help)
	}
	if !strings.Contains(help, "retroactively sandboxed") {
		t.Errorf("expected retroactive sandboxing explanation in adopt help, got:\n%s", help)
	}
}

func TestRestartHelp(t *testing.T) {
	help := cli.RenderHelp("shb", "restart")
	if !strings.Contains(help, "shb restart [agent]") {
		t.Errorf("expected usage in restart help, got:\n%s", help)
	}
	if !strings.Contains(help, "Stops an active SecretHarbor agent session") {
		t.Errorf("expected description in restart help, got:\n%s", help)
	}
}

func TestAdoptNoProcesses(t *testing.T) {
	defer func(orig func() ([]byte, error)) {
		agents.QueryProcessOutputForTest = orig
	}(agents.QueryProcessOutputForTest)
	agents.QueryProcessOutputForTest = func() ([]byte, error) {
		return []byte(""), nil
	}

	out, _ := captureStdoutAndStderr(func() {
		err := cli.RunAdopt("shb", []string{})
		if err != nil {
			t.Errorf("unexpected error in RunAdopt: %v", err)
		}
	})

	if !strings.Contains(out, "No unprotected agent processes found") &&
		!strings.Contains(out, "SecretHarbor Agent Adoption") {
		t.Errorf("unexpected output from RunAdopt: %s", out)
	}
}

func TestRestartNoProcesses(t *testing.T) {
	defer func(orig func() ([]byte, error)) {
		agents.QueryProcessOutputForTest = orig
	}(agents.QueryProcessOutputForTest)
	agents.QueryProcessOutputForTest = func() ([]byte, error) {
		return []byte(""), nil
	}

	out, errOut := captureStdoutAndStderr(func() {
		// Attempting restart when no process is running
		_ = cli.RunRestart("shb", []string{"nonexistent-agent-test"})
	})

	// When an explicit agent name is passed and no matching process is found,
	// it notes that no running process was found and attempts to initialize a fresh guarded session
	combined := out + errOut
	if !strings.Contains(combined, "No running process found for") &&
		!strings.Contains(combined, "no running agent sessions") {
		t.Errorf("expected process not found message, got:\n%s", combined)
	}
}

func TestInitHostIntegration(t *testing.T) {
	defer func(orig func() ([]byte, error)) {
		agents.QueryProcessOutputForTest = orig
	}(agents.QueryProcessOutputForTest)
	agents.QueryProcessOutputForTest = func() ([]byte, error) {
		return []byte(""), nil
	}

	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	// Set temporary SECRETHARBOR_DIR and HOME to test shim installation safely
	tmpHome := filepath.Join(tmpDir, "home")
	_ = os.MkdirAll(tmpHome, 0755)
	origHome := os.Getenv("HOME")
	origShbDir := os.Getenv("SECRETHARBOR_DIR")
	defer func() {
		_ = os.Setenv("HOME", origHome)
		_ = os.Setenv("SECRETHARBOR_DIR", origShbDir)
	}()

	_ = os.Setenv("HOME", tmpHome)
	_ = os.Setenv("SECRETHARBOR_DIR", filepath.Join(tmpHome, ".secretharbor"))

	out, _ := captureStdoutAndStderr(func() {
		err := cli.RunInit("shb", []string{})
		if err != nil {
			t.Fatalf("RunInit failed: %v", err)
		}
	})

	// 1. Verify secretharbor.yaml was created
	if _, err := os.Stat("secretharbor.yaml"); os.IsNotExist(err) {
		t.Fatalf("expected secretharbor.yaml to be created")
	}

	// 2. Verify shims directory exists
	shimsDir := filepath.Join(tmpHome, ".secretharbor", "shims")
	if _, err := os.Stat(shimsDir); os.IsNotExist(err) {
		t.Errorf("expected shims directory at %s", shimsDir)
	}

	// 3. Check output contents
	if !strings.Contains(out, "SecretHarbor initialized") {
		t.Errorf("expected initialization confirmation, got:\n%s", out)
	}
	if !strings.Contains(out, "Protection:") {
		t.Errorf("expected Protection header, got:\n%s", out)
	}
	if !strings.Contains(out, "Integration:") {
		t.Errorf("expected Integration header, got:\n%s", out)
	}
	if !strings.Contains(out, "Next steps:") {
		t.Errorf("expected Next steps section, got:\n%s", out)
	}
}

func TestStatusWithHostIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	tmpHome := filepath.Join(tmpDir, "home")
	_ = os.MkdirAll(tmpHome, 0755)
	origHome := os.Getenv("HOME")
	origShbDir := os.Getenv("SECRETHARBOR_DIR")
	defer func() {
		_ = os.Setenv("HOME", origHome)
		_ = os.Setenv("SECRETHARBOR_DIR", origShbDir)
	}()

	_ = os.Setenv("HOME", tmpHome)
	_ = os.Setenv("SECRETHARBOR_DIR", filepath.Join(tmpHome, ".secretharbor"))

	// Initialize
	if err := cli.RunInit("shb", []string{}); err != nil {
		t.Fatalf("RunInit failed: %v", err)
	}

	out, _ := captureStdoutAndStderr(func() {
		err := cli.RunStatus("shb")
		if err != nil {
			t.Fatalf("RunStatus failed: %v", err)
		}
	})

	if !strings.Contains(out, "Launcher Shims:") {
		t.Errorf("expected Launcher Shims line in status, got:\n%s", out)
	}
	if !strings.Contains(out, "Shell PATH:") {
		t.Errorf("expected Shell PATH line in status, got:\n%s", out)
	}
	if !strings.Contains(out, "Active Agent Sessions:") {
		t.Errorf("expected Active Agent Sessions in status, got:\n%s", out)
	}
	if !strings.Contains(out, "Unprotected Agent Processes:") {
		t.Errorf("expected Unprotected Agent Processes in status, got:\n%s", out)
	}
	if !strings.Contains(out, "Overall Posture:") {
		t.Errorf("expected Overall Posture in status, got:\n%s", out)
	}
}

func TestFailClosedDiagnostics(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(origWd) }()
	_ = os.Chdir(tmpDir)

	// Write an invalid policy that fails compilation
	_ = os.WriteFile("secretharbor.yaml", []byte("protection: invalid_mode_preset\n"), 0644)

	_, errOut := captureStdoutAndStderr(func() {
		_ = cli.RunAgent("shb", []string{"claude"})
	})

	if !strings.Contains(errOut, "SecretHarbor enforcement unavailable") {
		t.Errorf("expected 'SecretHarbor enforcement unavailable' in error output, got:\n%s", errOut)
	}
	if !strings.Contains(errOut, "cannot be started safely") {
		t.Errorf("expected 'cannot be started safely' in error output, got:\n%s", errOut)
	}
	if !strings.Contains(errOut, "Reason:") {
		t.Errorf("expected 'Reason:' in error output, got:\n%s", errOut)
	}
}

func TestAdoptGroupingSinglePrompt(t *testing.T) {
	defer func(orig func() ([]byte, error)) {
		agents.QueryProcessOutputForTest = orig
	}(agents.QueryProcessOutputForTest)

	// Simulate 1 VS Code main process and 2 helper processes with spaces in app path
	simulatedPS := `  PID  PPID COMMAND
  671     1 /Applications/Visual Studio Code.app/Contents/MacOS/Code
 1057   671 /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper --type=gpu-process
 1058   671 /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper --type=utility
`
	agents.QueryProcessOutputForTest = func() ([]byte, error) {
		return []byte(simulatedPS), nil
	}

	out, _ := captureStdoutAndStderr(func() {
		_ = cli.RunAdopt("shb", []string{})
	})

	// Must group the 3 processes into 1 application
	if !strings.Contains(out, "Found 1 agent application(s) (3 total processes)") {
		t.Errorf("expected 1 application with 3 total processes, got:\n%s", out)
	}
	if !strings.Contains(out, "PID 671     (3 processes)") {
		t.Errorf("expected root PID 671 with (3 processes) indicator, got:\n%s", out)
	}
	// In non-interactive test pipe, it should skip VS Code ONCE
	countSkipped := strings.Count(out, "Skipped VS Code")
	if countSkipped != 1 {
		t.Errorf("expected exactly 1 skip message, got %d:\n%s", countSkipped, out)
	}
}
