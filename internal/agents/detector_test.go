package agents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectInstalledAgents(t *testing.T) {
	agents := DetectInstalledAgents()
	// Should return slice without crashing
	for _, a := range agents {
		if a.ID == "" || a.DisplayName == "" || a.Path == "" {
			t.Errorf("incomplete detected agent struct: %+v", a)
		}
	}
}

func TestMatchesAgentCommand(t *testing.T) {
	cases := []struct {
		cmdLine  string
		agentID  string
		expected bool
	}{
		{"node /usr/local/bin/claude", "claude", true},
		{"node /path/to/@anthropic-ai/claude-code/cli.js", "claude", true},
		{"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "claude", false},
		{"codex run", "codex", true},
		{"ffmpeg -codecs", "codex", false},
		{"gemini prompt", "gemini", true},
		{"/Applications/Cursor.app/Contents/MacOS/Cursor", "cursor", true},
		{"cursor-server --port 1234", "cursor", true},
		{"aider --model gpt-4", "aider", true},
		{"/Applications/Antigravity.app/Contents/MacOS/Antigravity", "antigravity", true},
		{"agy run prompt", "antigravity", true},
		{"/opt/homebrew/bin/kiro", "kiro", true},
		{"/Applications/Kiro.app/Contents/MacOS/Electron", "kiro", true},
		{"/Applications/OpenCode.app/Contents/MacOS/OpenCode", "opencode", true},
		{"opencode serve", "opencode", true},
		{"pi prompt.md", "pi", true},
		{"node /path/to/@mariozechner/pi/bin.js", "pi", true},
		{"ohmypi start", "ohmypi", true},
		{"omp --model claude-3-7", "ohmypi", true},
		{"dsh web", "deepseek", true},
		{"node /path/to/@deepseek-ai/dsh/cli.js", "deepseek", true},
		{"/Applications/Windsurf.app/Contents/MacOS/Windsurf", "windsurf", true},
		{"/Applications/GitHub Copilot.app/Contents/MacOS/github", "copilot", true},
		{"goose session start", "goose", true},
		{"roo-cline run", "roo", true},
		{"/Applications/Zed.app/Contents/MacOS/Zed", "zed", true},
		{"ollama run codellama", "ollama", true},
		{"/Applications/Ollama.app/Contents/MacOS/Ollama", "ollama", true},
		{"openhands --port 3000", "openhands", true},
		{"devin run task", "devin", true},
		{"q chat --model bedrock", "amazon-q", true},
		{"cody chat", "cody", true},
		{"continue --gui", "continue", true},
		{"mentat /path/to/project", "mentat", true},
		{"/Applications/Claude.app/Contents/MacOS/Claude", "claude-desktop", true},
	}

	for _, tc := range cases {
		actual := matchesAgentCommand(tc.cmdLine, tc.agentID)
		if actual != tc.expected {
			t.Errorf("matchesAgentCommand(%q, %q) = %v, expected %v", tc.cmdLine, tc.agentID, actual, tc.expected)
		}
	}
}

func TestResolveAgentNewAgents(t *testing.T) {
	// Antigravity resolution
	target, err := ResolveAgent("antigravity", []string{"--version"})
	if err == nil {
		if target.Name != "antigravity" {
			t.Errorf("expected target name 'antigravity', got %q", target.Name)
		}
	}

	// Kiro resolution
	targetKiro, err := ResolveAgent("kiro", []string{"--version"})
	if err == nil {
		if targetKiro.Name != "kiro" {
			t.Errorf("expected target name 'kiro', got %q", targetKiro.Name)
		}
	}

	// OpenCode resolution
	targetOpenCode, err := ResolveAgent("opencode", []string{"--version"})
	if err == nil {
		if targetOpenCode.Name != "opencode" {
			t.Errorf("expected target name 'opencode', got %q", targetOpenCode.Name)
		}
	}

	// Ollama resolution
	targetOllama, err := ResolveAgent("ollama", []string{"--version"})
	if err == nil {
		if targetOllama.Name != "ollama" {
			t.Errorf("expected target name 'ollama', got %q", targetOllama.Name)
		}
	}

	// Pi runner fallback resolution
	targetPi, err := ResolveAgent("pi", []string{"test"})
	if err == nil {
		if targetPi.Name != "pi" {
			t.Errorf("expected target name 'pi', got %q", targetPi.Name)
		}
	}

	// DeepSeek runner fallback resolution
	targetDsh, err := ResolveAgent("deepseek", []string{"test"})
	if err == nil {
		if targetDsh.Name != "deepseek" {
			t.Errorf("expected target name 'deepseek', got %q", targetDsh.Name)
		}
	}
}

func TestInstallShims(t *testing.T) {
	tmpDir := t.TempDir()

	mockDetected := []*DetectedAgent{
		{
			ID:          "claude",
			DisplayName: "Claude Code",
			Type:        AgentTypeCLI,
			Path:        "/usr/local/bin/claude",
			Installed:   true,
		},
		{
			ID:          "cursor",
			DisplayName: "Cursor",
			Type:        AgentTypeDesktop,
			Path:        "/Applications/Cursor.app",
			Installed:   true,
		},
	}

	count, err := InstallShims(tmpDir, mockDetected)
	if err != nil {
		t.Fatalf("InstallShims failed: %v", err)
	}

	if count != 1 {
		t.Errorf("expected 1 CLI shim installed, got %d", count)
	}

	shimPath := filepath.Join(tmpDir, "claude")
	content, err := os.ReadFile(shimPath)
	if err != nil {
		t.Fatalf("failed to read created shim: %v", err)
	}

	shimStr := string(content)
	if !strings.Contains(shimStr, "SECRETHARBOR_SANDBOX") {
		t.Errorf("expected SECRETHARBOR_SANDBOX check in shim")
	}
	if !strings.Contains(shimStr, "shb run claude") {
		t.Errorf("expected shb run claude in shim")
	}
	if !strings.Contains(shimStr, "/usr/local/bin/claude") {
		t.Errorf("expected real binary fallback in shim")
	}
}

func TestAgentDecoupledModel(t *testing.T) {
	claude := &Agent{
		ID:          "claude",
		DisplayName: "Claude Code",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
	}
	if claude.Runtime != RuntimeProcess || claude.Integration != IntegrationCLI {
		t.Errorf("unexpected runtime or integration: %+v", claude)
	}

	cline := &Agent{
		ID:          "cline",
		DisplayName: "Cline",
		Runtime:     RuntimeProcess,
		Integration: IntegrationExtension,
	}
	if cline.Integration != IntegrationExtension {
		t.Errorf("expected cline integration to be extension, got %s", cline.Integration)
	}
}

func TestUnknownAgent(t *testing.T) {
	unknown := UnknownAgent("/usr/bin/custom-agent-tool")
	if unknown.ID != "unknown" {
		t.Errorf("expected ID 'unknown', got %s", unknown.ID)
	}
	if unknown.DisplayName != "custom-agent-tool" {
		t.Errorf("expected DisplayName 'custom-agent-tool', got %s", unknown.DisplayName)
	}
	if unknown.Runtime != RuntimeProcess {
		t.Errorf("expected RuntimeProcess, got %s", unknown.Runtime)
	}
	if unknown.Integration != IntegrationUnknown {
		t.Errorf("expected IntegrationUnknown, got %s", unknown.Integration)
	}
}

func TestGroupAgentProcessesVSCodeHelpers(t *testing.T) {
	// Simulate VS Code main process and child helper processes
	mainProc := &RunningAgentProcess{
		AgentID:     "vscode",
		DisplayName: "VS Code",
		PID:         671,
		PPID:        1,
		Command:     "/Applications/Visual Studio Code.app/Contents/MacOS/Code",
		Protected:   false,
	}
	gpuHelper := &RunningAgentProcess{
		AgentID:     "vscode",
		DisplayName: "VS Code",
		PID:         1057,
		PPID:        671,
		Command:     "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper.app/Contents/MacOS/Code Helper --type=gpu-process",
		Protected:   false,
	}
	rendererHelper := &RunningAgentProcess{
		AgentID:     "vscode",
		DisplayName: "VS Code",
		PID:         44888,
		PPID:        671,
		Command:     "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Renderer).app/Contents/MacOS/Code Helper (Renderer) --type=renderer",
		Protected:   false,
	}
	crashpadHelper := &RunningAgentProcess{
		AgentID:     "vscode",
		DisplayName: "VS Code",
		PID:         1052,
		PPID:        1, // Reparented to launchd
		Command:     "/Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Helpers/chrome_crashpad_handler",
		Protected:   false,
	}

	procs := []*RunningAgentProcess{mainProc, gpuHelper, rendererHelper, crashpadHelper}
	groups := GroupAgentProcesses(procs)

	if len(groups) != 1 {
		t.Fatalf("expected 1 grouped application, got %d", len(groups))
	}

	g := groups[0]
	if g.RootProcess.PID != 671 {
		t.Errorf("expected root PID 671, got %d", g.RootProcess.PID)
	}
	if len(g.AllPIDs) != 4 {
		t.Errorf("expected 4 all PIDs, got %d (%v)", len(g.AllPIDs), g.AllPIDs)
	}
	if len(g.HelperProcesses) != 3 {
		t.Errorf("expected 3 helper processes, got %d", len(g.HelperProcesses))
	}
	if !g.IsGUIApp() {
		t.Errorf("expected IsGUIApp() to be true")
	}
	if !strings.Contains(g.AppBundle, "Visual Studio Code.app") {
		t.Errorf("expected AppBundle to contain 'Visual Studio Code.app', got: %s", g.AppBundle)
	}
}

func TestExtractAppBundleAndExecutable(t *testing.T) {
	cmd := "/Applications/Visual Studio Code.app/Contents/MacOS/Code --user-data-dir /tmp/test"
	bundle := ExtractAppBundle(cmd)
	if bundle != "/Applications/Visual Studio Code.app" {
		t.Errorf("expected bundle '/Applications/Visual Studio Code.app', got %q", bundle)
	}

	cmd2 := "/Applications/OpenCode.app/Contents/MacOS/OpenCode"
	bundle2 := ExtractAppBundle(cmd2)
	if bundle2 != "/Applications/OpenCode.app" {
		t.Errorf("expected bundle '/Applications/OpenCode.app', got %q", bundle2)
	}

	cmdCLI := "opencode run 'fix bug'"
	bundleCLI := ExtractAppBundle(cmdCLI)
	if bundleCLI != "" {
		t.Errorf("expected empty bundle for CLI, got %q", bundleCLI)
	}
}

func TestResolveAgentGUIAppAliases(t *testing.T) {
	// Test that GUI alias cases exist and map cleanly
	for _, alias := range []string{"opencode-app", "vscode-app", "cursor-app", "antigravity-app", "kiro-app", "windsurf-app", "zed-app", "claude-app", "ollama-app"} {
		target, err := ResolveAgent(alias, []string{"--test-flag"})
		// Target should either resolve or return friendly install error mentioning the app
		if err != nil {
			errStr := strings.ToLower(err.Error())
			if !strings.Contains(errStr, "not installed") && !strings.Contains(errStr, "download") {
				t.Errorf("unexpected error for %s: %v", alias, err)
			}
		} else if target != nil {
			if len(target.Args) == 0 || target.Args[len(target.Args)-1] != "--test-flag" {
				t.Errorf("expected args to include '--test-flag', got: %v", target.Args)
			}
			if IsElectronOrChromiumApp(target.Command) {
				for _, a := range target.Args {
					if a == "--no-sandbox" {
						t.Errorf("ResolveAgent must not disable the Electron/Chromium renderer sandbox for %s, got: %v", alias, target.Args)
						break
					}
				}
			}
		}
	}
}

func TestElectronDetectionAndNoSandbox(t *testing.T) {
	cases := []struct {
		path       string
		isElectron bool
	}{
		{"/Applications/OpenCode.app/Contents/MacOS/OpenCode", true},
		{"/Applications/Antigravity.app/Contents/MacOS/Antigravity", true},
		{"/Applications/Visual Studio Code.app/Contents/MacOS/Code", true},
		{"/Applications/Cursor.app/Contents/MacOS/Cursor", true},
		{"/Applications/Kiro.app/Contents/MacOS/Kiro", true},
		{"/usr/local/bin/git", false},
		{"/bin/bash", false},
		{"opencode", false},
	}

	for _, tc := range cases {
		got := IsElectronOrChromiumApp(tc.path)
		if got != tc.isElectron {
			t.Errorf("IsElectronOrChromiumApp(%q) = %v; want %v", tc.path, got, tc.isElectron)
		}
	}

	args := EnsureNoSandboxArg([]string{"--foo", "bar"})
	if len(args) != 3 || args[0] != "--no-sandbox" {
		t.Errorf("expected --no-sandbox prepended, got: %v", args)
	}

	// Should not duplicate if already present
	args2 := EnsureNoSandboxArg(args)
	if len(args2) != 3 {
		t.Errorf("expected no duplication of --no-sandbox, got: %v", args2)
	}
}
