package agents

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// AgentRuntime defines the execution and isolation environment of the agent.
type AgentRuntime string

const (
	RuntimeProcess   AgentRuntime = "process"   // Native host process execution
	RuntimeContainer AgentRuntime = "container" // Inside Docker / Podman / devcontainer
	RuntimeRemote    AgentRuntime = "remote"    // Remote machine / SSH / cloud box
	RuntimeEmbedded  AgentRuntime = "embedded"  // Embedded inside host application
)

// AgentIntegration defines the interaction and deployment interface.
type AgentIntegration string

const (
	IntegrationCLI       AgentIntegration = "cli"       // Interactive CLI agent (claude, codex, gemini)
	IntegrationDesktop   AgentIntegration = "desktop"   // Dedicated desktop application (Claude Desktop)
	IntegrationIDE       AgentIntegration = "ide"       // Host IDE (Cursor, VS Code)
	IntegrationExtension AgentIntegration = "extension" // Sub-agent running in IDE extension host (Cline)
	IntegrationServer    AgentIntegration = "server"    // Background daemon / local agent service
	IntegrationUnknown   AgentIntegration = "unknown"   // Unknown or generic command execution
)

// Deprecated type alias for backwards compatibility
type AgentType = AgentIntegration

const (
	AgentTypeCLI     = IntegrationCLI
	AgentTypeDesktop = IntegrationDesktop
	AgentTypeIDE     = IntegrationIDE
)

// Agent represents an identified or recognized agent definition.
type Agent struct {
	ID          string           `json:"id"`
	DisplayName string           `json:"display_name"`
	Runtime     AgentRuntime     `json:"runtime"`
	Integration AgentIntegration `json:"integration"`
	Type        AgentIntegration `json:"type"` // Backwards compatibility alias for Integration
	Path        string           `json:"path"`
	Installed   bool             `json:"installed"`
	PackageType string           `json:"package_type"` // "native", "npm", "app_bundle", etc.
}

// DetectedAgent is a type alias to Agent for backwards compatibility.
type DetectedAgent = Agent

// UnknownAgent creates a fallback Agent definition for unrecognized commands.
// Per SecretHarbor's fail-safe invariant, unknown agents are treated as untrusted
// and subject to full standard sandboxing.
func UnknownAgent(command string) *Agent {
	name := filepath.Base(command)
	if name == "" || name == "." {
		name = "unknown"
	}
	return &Agent{
		ID:          "unknown",
		DisplayName: name,
		Runtime:     RuntimeProcess,
		Integration: IntegrationUnknown,
		Type:        IntegrationUnknown,
		Path:        command,
		Installed:   true,
		PackageType: "native",
	}
}

// SupportedAgentsRegistry lists the known AI agents and desktop environments supported by SecretHarbor.
var SupportedAgentsRegistry = []struct {
	ID          string
	DisplayName string
	Runtime     AgentRuntime
	Integration AgentIntegration
	Type        AgentIntegration
	BinaryNames []string
	DesktopDirs []string
}{
	{
		ID:          "claude",
		DisplayName: "Claude Code",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"claude", "claude-code"},
	},
	{
		ID:          "codex",
		DisplayName: "Codex",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"codex"},
	},
	{
		ID:          "gemini",
		DisplayName: "Gemini CLI",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"gemini"},
	},
	{
		ID:          "cursor",
		DisplayName: "Cursor",
		Runtime:     RuntimeProcess,
		Integration: IntegrationIDE,
		Type:        IntegrationIDE,
		BinaryNames: []string{"cursor"},
		DesktopDirs: []string{
			"/Applications/Cursor.app",
			"~/Applications/Cursor.app",
			"/usr/share/applications/cursor.desktop",
		},
	},
	{
		ID:          "aider",
		DisplayName: "Aider",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"aider"},
	},
	{
		ID:          "cline",
		DisplayName: "Cline",
		Runtime:     RuntimeProcess,
		Integration: IntegrationExtension,
		Type:        IntegrationExtension,
		BinaryNames: []string{"cline"},
	},
	{
		ID:          "antigravity",
		DisplayName: "Google Antigravity",
		Runtime:     RuntimeProcess,
		Integration: IntegrationIDE,
		Type:        IntegrationIDE,
		BinaryNames: []string{"agy", "antigravity", "antigravity-ide", "agy-ide"},
		DesktopDirs: []string{
			"/Applications/Antigravity.app",
			"~/Applications/Antigravity.app",
			"/Applications/Antigravity IDE.app",
			"~/Applications/Antigravity IDE.app",
		},
	},
	{
		ID:          "kiro",
		DisplayName: "Kiro (AWS)",
		Runtime:     RuntimeProcess,
		Integration: IntegrationIDE,
		Type:        IntegrationIDE,
		BinaryNames: []string{"kiro"},
		DesktopDirs: []string{
			"/Applications/Kiro.app",
			"~/Applications/Kiro.app",
			"/usr/share/applications/kiro.desktop",
		},
	},
	{
		ID:          "opencode",
		DisplayName: "OpenCode",
		Runtime:     RuntimeProcess,
		Integration: IntegrationIDE,
		Type:        IntegrationIDE,
		BinaryNames: []string{"opencode"},
		DesktopDirs: []string{
			"/Applications/OpenCode.app",
			"~/Applications/OpenCode.app",
			"/usr/share/applications/opencode.desktop",
		},
	},
	{
		ID:          "pi",
		DisplayName: "Pi Coding Agent",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"pi", "pi-agent"},
	},
	{
		ID:          "ohmypi",
		DisplayName: "Oh-My-Pi",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"ohmypi", "omp"},
	},
	{
		ID:          "deepseek",
		DisplayName: "DeepSeek Harness",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"dsh", "deepseek-harness", "deepseek"},
	},
	{
		ID:          "windsurf",
		DisplayName: "Codeium Windsurf",
		Runtime:     RuntimeProcess,
		Integration: IntegrationIDE,
		Type:        IntegrationIDE,
		BinaryNames: []string{"windsurf"},
		DesktopDirs: []string{
			"/Applications/Windsurf.app",
			"~/Applications/Windsurf.app",
			"/usr/share/applications/windsurf.desktop",
		},
	},
	{
		ID:          "copilot",
		DisplayName: "GitHub Copilot",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"copilot", "github-copilot"},
		DesktopDirs: []string{
			"/Applications/GitHub Copilot.app",
			"~/Applications/GitHub Copilot.app",
		},
	},
	{
		ID:          "goose",
		DisplayName: "Goose",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"goose"},
	},
	{
		ID:          "roo",
		DisplayName: "Roo Code",
		Runtime:     RuntimeProcess,
		Integration: IntegrationExtension,
		Type:        IntegrationExtension,
		BinaryNames: []string{"roo", "roo-cline", "roo-code"},
	},
	{
		ID:          "zed",
		DisplayName: "Zed",
		Runtime:     RuntimeProcess,
		Integration: IntegrationIDE,
		Type:        IntegrationIDE,
		BinaryNames: []string{"zed"},
		DesktopDirs: []string{
			"/Applications/Zed.app",
			"~/Applications/Zed.app",
			"/usr/share/applications/zed.desktop",
		},
	},
	{
		ID:          "ollama",
		DisplayName: "Ollama",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"ollama"},
		DesktopDirs: []string{
			"/Applications/Ollama.app",
			"~/Applications/Ollama.app",
		},
	},
	{
		ID:          "openhands",
		DisplayName: "OpenHands",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"openhands", "all-hands"},
	},
	{
		ID:          "devin",
		DisplayName: "Devin CLI",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"devin"},
	},
	{
		ID:          "amazon-q",
		DisplayName: "Amazon Q Developer",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"q", "amazon-q", "aws-q"},
	},
	{
		ID:          "cody",
		DisplayName: "Sourcegraph Cody",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"cody", "cody-cli"},
	},
	{
		ID:          "continue",
		DisplayName: "Continue",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"continue"},
	},
	{
		ID:          "mentat",
		DisplayName: "Mentat",
		Runtime:     RuntimeProcess,
		Integration: IntegrationCLI,
		Type:        IntegrationCLI,
		BinaryNames: []string{"mentat"},
	},
	{
		ID:          "claude-desktop",
		DisplayName: "Claude Desktop",
		Runtime:     RuntimeProcess,
		Integration: IntegrationDesktop,
		Type:        AgentTypeDesktop,
		BinaryNames: []string{"claude-desktop"},
		DesktopDirs: []string{
			"/Applications/Claude.app",
			"~/Applications/Claude.app",
		},
	},
	{
		ID:          "vscode",
		DisplayName: "VS Code",
		Runtime:     RuntimeProcess,
		Integration: IntegrationIDE,
		Type:        IntegrationIDE,
		BinaryNames: []string{"code"},
		DesktopDirs: []string{
			"/Applications/Visual Studio Code.app",
			"~/Applications/Visual Studio Code.app",
			"/usr/share/applications/code.desktop",
		},
	},
}

// DetectInstalledAgents scans the host system for supported AI agents and desktop environments.
func DetectInstalledAgents() []*DetectedAgent {
	var detected []*DetectedAgent
	home, _ := os.UserHomeDir()

	for _, spec := range SupportedAgentsRegistry {
		var foundPath string
		packageType := "native"

		// 1. Check executable PATH (excluding our own shims)
		for _, binName := range spec.BinaryNames {
			if path, err := lookPathExcludingShims(binName); err == nil && path != "" {
				foundPath = path
				if strings.Contains(path, "node_modules") || strings.Contains(path, "npm") || strings.Contains(path, "npx") {
					packageType = "npm"
				}
				break
			}
		}

		// 2. Check desktop application locations if not found in PATH
		if foundPath == "" && len(spec.DesktopDirs) > 0 {
			for _, appPath := range spec.DesktopDirs {
				cleanPath := appPath
				if strings.HasPrefix(cleanPath, "~/") && home != "" {
					cleanPath = filepath.Join(home, cleanPath[2:])
				}
				if _, err := os.Stat(cleanPath); err == nil {
					foundPath = cleanPath
					packageType = "app_bundle"
					break
				}
			}
		}

		if foundPath != "" {
			detected = append(detected, &DetectedAgent{
				ID:          spec.ID,
				DisplayName: spec.DisplayName,
				Runtime:     spec.Runtime,
				Integration: spec.Integration,
				Type:        spec.Integration,
				Path:        foundPath,
				Installed:   true,
				PackageType: packageType,
			})
		}
	}

	return detected
}

// lookPathExcludingShims searches PATH for an executable, ignoring SecretHarbor shim directories.
func lookPathExcludingShims(file string) (string, error) {
	pathEnv := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(pathEnv) {
		if strings.Contains(dir, ".secretharbor/shims") || strings.Contains(dir, ".secretharbor/bin") {
			continue
		}
		candidate := filepath.Join(dir, file)
		if fi, err := os.Stat(candidate); err == nil && !fi.IsDir() {
			if runtime.GOOS == "windows" || fi.Mode()&0111 != 0 {
				return candidate, nil
			}
		}
	}
	return exec.LookPath(file)
}
