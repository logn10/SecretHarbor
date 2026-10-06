package agents

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// AgentTarget describes the target binary and arguments to execute.
type AgentTarget struct {
	Name     string
	Command  string
	Args     []string
	ExtraEnv []string
}

// ResolveAgent maps an agent identifier or CLI arguments to an executable target.
func ResolveAgent(alias string, customArgs []string) (*AgentTarget, error) {
	target, err := resolveAgentInternal(alias, customArgs)
	if err != nil {
		return nil, err
	}
	return target, nil
}

func resolveAgentInternal(alias string, customArgs []string) (*AgentTarget, error) {
	switch alias {
	case "claude":
		cmd, err := resolveCommand("claude", "npx", "-y", "@anthropic-ai/claude-code")
		if err != nil {
			return nil, err
		}
		return &AgentTarget{
			Name:    "claude",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "gemini":
		cmd, err := resolveCommand("gemini")
		if err != nil {
			return nil, err
		}
		return &AgentTarget{
			Name:    "gemini",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "codex":
		cmd, err := resolveCommand("codex")
		if err != nil {
			return nil, err
		}
		return &AgentTarget{
			Name:    "codex",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "cursor":
		cmd, err := resolveExecutable(
			[]string{
				"cursor",
				"/Applications/Cursor.app/Contents/MacOS/Cursor",
				"~/Applications/Cursor.app/Contents/MacOS/Cursor",
			},
		)
		if err != nil {
			return nil, err
		}
		return &AgentTarget{
			Name:    "cursor",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "cursor-app":
		cmd, err := resolveExecutable(
			[]string{
				"/Applications/Cursor.app/Contents/MacOS/Cursor",
				"~/Applications/Cursor.app/Contents/MacOS/Cursor",
				"cursor",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("Cursor.app is not installed. Download from https://cursor.com")
		}
		return &AgentTarget{
			Name:    "cursor",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "aider":
		cmd, err := resolveCommand("aider")
		if err != nil {
			return nil, err
		}
		return &AgentTarget{
			Name:    "aider",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "cline":
		cmd, err := resolveCommand("cline", "npx", "-y", "cline")
		if err != nil {
			return nil, err
		}
		return &AgentTarget{
			Name:    "cline",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "antigravity", "agy":
		cmd, err := resolveExecutable(
			[]string{
				"agy",
				"antigravity",
				"antigravity-ide",
				"/Applications/Antigravity.app/Contents/MacOS/Antigravity",
				"~/Applications/Antigravity.app/Contents/MacOS/Antigravity",
				"/Applications/Antigravity IDE.app/Contents/MacOS/Antigravity IDE",
				"~/Applications/Antigravity IDE.app/Contents/MacOS/Antigravity IDE",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("antigravity is not installed. Download from https://antigravity.google or install /Applications/Antigravity.app")
		}
		return &AgentTarget{
			Name:    "antigravity",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "antigravity-app", "agy-app":
		cmd, err := resolveExecutable(
			[]string{
				"/Applications/Antigravity.app/Contents/MacOS/Antigravity",
				"~/Applications/Antigravity.app/Contents/MacOS/Antigravity",
				"/Applications/Antigravity IDE.app/Contents/MacOS/Antigravity IDE",
				"~/Applications/Antigravity IDE.app/Contents/MacOS/Antigravity IDE",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("Antigravity.app is not installed. Download from https://antigravity.google")
		}
		return &AgentTarget{
			Name:    "antigravity",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "kiro":
		cmd, err := resolveExecutable(
			[]string{
				"kiro",
				"/Applications/Kiro.app/Contents/Resources/app/bin/code",
				"/Applications/Kiro.app/Contents/MacOS/Electron",
				"~/Applications/Kiro.app/Contents/Resources/app/bin/code",
				"~/Applications/Kiro.app/Contents/MacOS/Electron",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("kiro is not installed. Download from https://kiro.dev or install via brew (brew install kiro)")
		}
		return &AgentTarget{
			Name:    "kiro",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "kiro-app":
		cmd, err := resolveExecutable(
			[]string{
				"/Applications/Kiro.app/Contents/MacOS/Electron",
				"/Applications/Kiro.app/Contents/MacOS/Kiro",
				"~/Applications/Kiro.app/Contents/MacOS/Electron",
				"~/Applications/Kiro.app/Contents/MacOS/Kiro",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("Kiro.app is not installed. Download from https://kiro.dev")
		}
		return &AgentTarget{
			Name:    "kiro",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "opencode":
		cmd, err := resolveExecutable(
			[]string{
				"opencode",
				"/Applications/OpenCode.app/Contents/MacOS/OpenCode",
				"~/Applications/OpenCode.app/Contents/MacOS/OpenCode",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("opencode is not installed. Download from https://opencode.ai or install via brew")
		}
		return &AgentTarget{
			Name:    "opencode",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "opencode-app", "opencode-desktop":
		cmd, err := resolveExecutable(
			[]string{
				"/Applications/OpenCode.app/Contents/MacOS/OpenCode",
				"~/Applications/OpenCode.app/Contents/MacOS/OpenCode",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("OpenCode.app is not installed. Download from https://opencode.ai")
		}
		return &AgentTarget{
			Name:    "opencode",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "pi":
		cmd, err := resolveExecutable(
			[]string{"pi", "pi-agent"},
			"npx", "-y", "@mariozechner/pi",
		)
		if err != nil {
			return nil, fmt.Errorf("pi is not installed. Install via npm (npm install -g @mariozechner/pi) or ensure npx is installed")
		}
		return &AgentTarget{
			Name:    "pi",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "ohmypi", "omp":
		cmd, err := resolveExecutable(
			[]string{"ohmypi", "omp"},
			"npx", "-y", "oh-my-pi",
		)
		if err != nil {
			return nil, fmt.Errorf("oh-my-pi is not installed. Install via npm (npm install -g oh-my-pi) or ensure npx is installed")
		}
		return &AgentTarget{
			Name:    "ohmypi",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "deepseek", "dsh":
		cmd, err := resolveExecutable(
			[]string{"dsh", "deepseek-harness", "deepseek"},
			"npx", "-y", "@deepseek-ai/dsh",
		)
		if err != nil {
			return nil, fmt.Errorf("deepseek harness is not installed. Install via npm (npm install -g @deepseek-ai/dsh) or ensure npx is installed")
		}
		return &AgentTarget{
			Name:    "deepseek",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "windsurf":
		cmd, err := resolveExecutable(
			[]string{
				"windsurf",
				"/Applications/Windsurf.app/Contents/MacOS/Windsurf",
				"~/Applications/Windsurf.app/Contents/MacOS/Windsurf",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("windsurf is not installed. Download from https://codeium.com/windsurf")
		}
		return &AgentTarget{
			Name:    "windsurf",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "windsurf-app":
		cmd, err := resolveExecutable(
			[]string{
				"/Applications/Windsurf.app/Contents/MacOS/Windsurf",
				"~/Applications/Windsurf.app/Contents/MacOS/Windsurf",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("Windsurf.app is not installed. Download from https://codeium.com/windsurf")
		}
		return &AgentTarget{
			Name:    "windsurf",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "copilot", "github-copilot":
		cmd, err := resolveExecutable(
			[]string{
				"copilot",
				"github-copilot",
				"/Applications/GitHub Copilot.app/Contents/MacOS/github",
				"~/Applications/GitHub Copilot.app/Contents/MacOS/github",
			},
			"gh", "copilot",
		)
		if err != nil {
			return nil, fmt.Errorf("github copilot is not installed. Install via gh extension install github/gh-copilot or download GitHub Copilot.app")
		}
		return &AgentTarget{
			Name:    "copilot",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "copilot-app":
		cmd, err := resolveExecutable(
			[]string{
				"/Applications/GitHub Copilot.app/Contents/MacOS/github",
				"~/Applications/GitHub Copilot.app/Contents/MacOS/github",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("GitHub Copilot.app is not installed.")
		}
		return &AgentTarget{
			Name:    "copilot",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "goose":
		cmd, err := resolveExecutable(
			[]string{"goose"},
		)
		if err != nil {
			return nil, fmt.Errorf("goose is not installed. Download from https://block.github.io/goose or install via brew (brew install block/goose/goose)")
		}
		return &AgentTarget{
			Name:    "goose",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "roo", "roo-cline", "roo-code":
		cmd, err := resolveExecutable(
			[]string{"roo", "roo-cline", "roo-code"},
			"npx", "-y", "roo-cline",
		)
		if err != nil {
			return nil, fmt.Errorf("roo is not installed. Install via npm (npm install -g roo-cline) or ensure npx is installed")
		}
		return &AgentTarget{
			Name:    "roo",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "zed":
		cmd, err := resolveExecutable(
			[]string{
				"zed",
				"/Applications/Zed.app/Contents/MacOS/Zed",
				"~/Applications/Zed.app/Contents/MacOS/Zed",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("zed is not installed. Download from https://zed.dev")
		}
		return &AgentTarget{
			Name:    "zed",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "zed-app":
		cmd, err := resolveExecutable(
			[]string{
				"/Applications/Zed.app/Contents/MacOS/Zed",
				"~/Applications/Zed.app/Contents/MacOS/Zed",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("Zed.app is not installed. Download from https://zed.dev")
		}
		return &AgentTarget{
			Name:    "zed",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "ollama":
		cmd, err := resolveExecutable(
			[]string{
				"ollama",
				"/usr/local/bin/ollama",
				"/Applications/Ollama.app/Contents/Resources/ollama",
				"/Applications/Ollama.app/Contents/MacOS/Ollama",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("ollama is not installed. Download from https://ollama.com or install via brew (brew install ollama)")
		}
		return &AgentTarget{
			Name:    "ollama",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "ollama-app":
		cmd, err := resolveExecutable(
			[]string{
				"/Applications/Ollama.app/Contents/MacOS/Ollama",
				"~/Applications/Ollama.app/Contents/MacOS/Ollama",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("Ollama.app is not installed. Download from https://ollama.com")
		}
		return &AgentTarget{
			Name:    "ollama",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "openhands", "all-hands":
		cmd, err := resolveExecutable(
			[]string{"openhands", "all-hands"},
			"poetry", "run", "openhands",
		)
		if err != nil {
			return nil, fmt.Errorf("openhands is not installed. Install via pip/docker: see https://github.com/All-Hands-AI/OpenHands")
		}
		return &AgentTarget{
			Name:    "openhands",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "devin":
		cmd, err := resolveExecutable(
			[]string{"devin"},
		)
		if err != nil {
			return nil, fmt.Errorf("devin CLI is not installed. See https://devin.ai/cli")
		}
		return &AgentTarget{
			Name:    "devin",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "amazon-q", "q", "aws-q":
		cmd, err := resolveExecutable(
			[]string{"q", "amazon-q", "aws-q"},
		)
		if err != nil {
			return nil, fmt.Errorf("amazon q is not installed. Download from https://aws.amazon.com/q/developer")
		}
		return &AgentTarget{
			Name:    "amazon-q",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "cody", "cody-cli":
		cmd, err := resolveExecutable(
			[]string{"cody", "cody-cli"},
			"npx", "-y", "@sourcegraph/cody",
		)
		if err != nil {
			return nil, fmt.Errorf("cody is not installed. Install via npm (npm install -g @sourcegraph/cody) or ensure npx is installed")
		}
		return &AgentTarget{
			Name:    "cody",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "continue":
		cmd, err := resolveExecutable(
			[]string{"continue"},
			"npx", "-y", "continue",
		)
		if err != nil {
			return nil, fmt.Errorf("continue is not installed. See https://continue.dev")
		}
		return &AgentTarget{
			Name:    "continue",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "mentat":
		cmd, err := resolveExecutable(
			[]string{"mentat"},
		)
		if err != nil {
			return nil, fmt.Errorf("mentat is not installed. Install via pip (pip install mentat)")
		}
		return &AgentTarget{
			Name:    "mentat",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "claude-desktop", "claude-app":
		cmd, err := resolveExecutable(
			[]string{
				"claude-desktop",
				"/Applications/Claude.app/Contents/MacOS/Claude",
				"~/Applications/Claude.app/Contents/MacOS/Claude",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("claude desktop is not installed. Download from https://claude.ai/download")
		}
		return &AgentTarget{
			Name:    "claude-desktop",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "vscode", "code":
		cmd, err := resolveExecutable(
			[]string{
				"code",
				"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
				"/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
				"/Applications/Visual Studio Code.app/Contents/MacOS/Code",
				"~/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
				"~/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
				"~/Applications/Visual Studio Code.app/Contents/MacOS/Code",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("vscode is not installed. Download from https://code.visualstudio.com")
		}
		return &AgentTarget{
			Name:    "vscode",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "vscode-app", "code-app":
		cmd, err := resolveExecutable(
			[]string{
				"/Applications/Visual Studio Code.app/Contents/MacOS/Code",
				"/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
				"~/Applications/Visual Studio Code.app/Contents/MacOS/Code",
				"~/Applications/Visual Studio Code.app/Contents/MacOS/Electron",
				"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
			},
		)
		if err != nil {
			return nil, fmt.Errorf("Visual Studio Code.app is not installed. Download from https://code.visualstudio.com")
		}
		return &AgentTarget{
			Name:    "vscode",
			Command: cmd[0],
			Args:    append(cmd[1:], customArgs...),
		}, nil

	case "--", "generic", "":
		if len(customArgs) == 0 {
			return nil, fmt.Errorf("no command provided for execution")
		}
		return &AgentTarget{
			Name:    "generic",
			Command: customArgs[0],
			Args:    customArgs[1:],
		}, nil

	default:
		// Direct execution if binary exists or look in PATH
		if path, err := exec.LookPath(alias); err == nil {
			return &AgentTarget{
				Name:    filepath.Base(alias),
				Command: path,
				Args:    customArgs,
			}, nil
		}
		if fi, err := os.Stat(alias); err == nil && !fi.IsDir() {
			return &AgentTarget{
				Name:    filepath.Base(alias),
				Command: alias,
				Args:    customArgs,
			}, nil
		}
		return &AgentTarget{
			Name:    alias,
			Command: alias,
			Args:    customArgs,
		}, nil
	}
}

func resolveExecutable(candidates []string, fallbackRunner ...string) ([]string, error) {
	home, _ := os.UserHomeDir()
	for _, c := range candidates {
		target := c
		if strings.HasPrefix(target, "~/") && home != "" {
			target = filepath.Join(home, target[2:])
		}
		if filepath.IsAbs(target) {
			if fi, err := os.Stat(target); err == nil && !fi.IsDir() {
				return []string{target}, nil
			}
		} else {
			if path, err := exec.LookPath(target); err == nil {
				return []string{path}, nil
			}
		}
	}
	if len(fallbackRunner) > 0 {
		if path, err := exec.LookPath(fallbackRunner[0]); err == nil {
			return append([]string{path}, fallbackRunner[1:]...), nil
		}
	}
	return nil, fmt.Errorf("executable not found in candidates %v", candidates)
}

func resolveCommand(primary string, fallback ...string) ([]string, error) {
	if path, err := exec.LookPath(primary); err == nil {
		return []string{path}, nil
	}
	if len(fallback) > 0 {
		if path, err := exec.LookPath(fallback[0]); err == nil {
			return append([]string{path}, fallback[1:]...), nil
		}
	}
	return []string{primary}, nil
}

// IsElectronOrChromiumApp checks if an executable path belongs to an Electron or Chromium application.
func IsElectronOrChromiumApp(exePath string) bool {
	if exePath == "" {
		return false
	}
	clean := filepath.Clean(exePath)
	lower := strings.ToLower(clean)

	// Direct check for electron binary
	base := strings.ToLower(filepath.Base(clean))
	if base == "electron" || strings.HasPrefix(base, "electron-") {
		return true
	}

	// Known Electron desktop apps
	knownElectronNames := []string{
		"opencode", "antigravity", "cursor", "kiro",
		"windsurf", "claude", "electron",
	}

	// Check macOS .app bundle structure
	if idx := strings.Index(lower, ".app/contents/macos/"); idx != -1 {
		bundlePath := clean[:idx+4]
		frameworksDir := filepath.Join(bundlePath, "Contents", "Frameworks")
		if fi, err := os.Stat(frameworksDir); err == nil && fi.IsDir() {
			// Check for Electron Framework or Chromium Framework
			if _, err := os.Stat(filepath.Join(frameworksDir, "Electron Framework.framework")); err == nil {
				return true
			}
			if _, err := os.Stat(filepath.Join(frameworksDir, "Chromium Embedded Framework.framework")); err == nil {
				return true
			}
			// Check for any helper app with GPU or Renderer in frameworks
			entries, _ := os.ReadDir(frameworksDir)
			for _, entry := range entries {
				ename := entry.Name()
				if strings.Contains(ename, "Helper") || strings.Contains(ename, "GPU") {
					return true
				}
			}
		}

		// Also check if app bundle name or binary matches known Electron app names
		for _, k := range knownElectronNames {
			if strings.Contains(lower, k) {
				return true
			}
		}
		if base == "code" || strings.Contains(lower, "visual studio code") {
			return true
		}
	}

	return false
}

// EnsureNoSandboxArg ensures that --no-sandbox is included in args for Chromium/Electron apps.
func EnsureNoSandboxArg(args []string) []string {
	for _, a := range args {
		if a == "--no-sandbox" {
			return args
		}
	}
	return append([]string{"--no-sandbox"}, args...)
}
