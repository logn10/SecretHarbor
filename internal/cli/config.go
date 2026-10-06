package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/secretharbor/secretharbor/internal/policy"
	"github.com/secretharbor/secretharbor/internal/vault"
	"gopkg.in/yaml.v3"
)

// EffectivePolicyView is the machine-readable and human-readable representation of intended enforcement.
type EffectivePolicyView struct {
	Protection  string            `json:"protection"`
	Guard       string            `json:"guard"`
	Secrets     map[string]string `json:"secrets"`     // pattern/resource -> effective mode (fake, deny, allow)
	Environment map[string]string `json:"environment"` // var -> effective treatment (sanitize, stripped, allow)
	Network     NetworkView       `json:"network"`
	IPC         IPCView           `json:"ipc"`
	Sandbox     SandboxView       `json:"sandbox"`
	Trusted     []string          `json:"trusted,omitempty"`
}

type NetworkView struct {
	Mode    string   `json:"mode"`
	Allowed []string `json:"allowed"`
}

type IPCView struct {
	UnixSockets     string `json:"unix_sockets"`
	AbstractSockets string `json:"abstract_sockets"`
	Docker          string `json:"docker"`
}

type SandboxView struct {
	Escape string `json:"escape"`
}

// RuleSource describes the provenance and origin of an effective rule.
type RuleSource struct {
	Resource string `json:"resource"`
	Mode     string `json:"mode"`
	Source   string `json:"source"`
}

// RunConfig handles `shb config` and all its subcommands.
func RunConfig(progName string, args []string) error {
	sub := "show"
	var subArgs []string
	if len(args) > 0 {
		sub = strings.ToLower(args[0])
		subArgs = args[1:]
	}

	switch sub {
	case "show":
		return runConfigShow(progName, subArgs)
	case "get":
		return runConfigGet(progName, subArgs)
	case "set":
		return runConfigSet(progName, subArgs)
	case "source":
		return runConfigSource(progName, subArgs)
	case "check":
		return runConfigCheck(progName, subArgs)
	case "edit":
		return runConfigEdit(progName, subArgs)
	case "diff":
		return runConfigDiff(progName, subArgs)
	default:
		// Check if first arg was a flag like --json
		if strings.HasPrefix(sub, "-") {
			return runConfigShow(progName, args)
		}
		return fmt.Errorf("unknown config action %q. Usage: %s config [show|get|set|check|edit|diff|source]", sub, progName)
	}
}

func getEffectivePolicy(cwd string) (*policy.Config, string, *EffectivePolicyView, error) {
	cfg, configPath, err := policy.LoadPolicy(cwd)
	if err != nil {
		return nil, "", nil, err
	}

	envMap := make(map[string]string)
	envMap["Mode"] = string(cfg.Environment.Mode)
	for _, p := range policy.PrivilegedIPCEmptyVars {
		envMap[p] = "stripped"
	}
	for _, d := range cfg.Environment.Deny {
		envMap[d] = "denied"
	}
	for _, f := range cfg.Environment.Fake {
		envMap[f] = "fake"
	}
	for _, a := range cfg.Environment.Allow {
		envMap[a] = "allowed"
	}

	secMap := make(map[string]string)
	secMap["Mode"] = string(cfg.Secrets.Mode)
	for _, r := range cfg.Rules {
		if r.Read != "" {
			secMap[r.Secret] = string(r.Read)
		}
	}

	guardState := "on"
	if !cfg.IsGuardEnabled() {
		guardState = "off"
	}

	view := &EffectivePolicyView{
		Protection:  string(cfg.Protection),
		Guard:       guardState,
		Secrets:     secMap,
		Environment: envMap,
		Network: NetworkView{
			Mode:    string(cfg.Network.Mode),
			Allowed: append([]string(nil), cfg.Network.Allow...),
		},
		IPC: IPCView{
			UnixSockets:     string(cfg.IPC.UnixSockets.Mode),
			AbstractSockets: string(cfg.IPC.AbstractSockets.Mode),
			Docker:          string(cfg.IPC.Docker.Mode),
		},
		Sandbox: SandboxView{
			Escape: string(cfg.Sandbox.Escape),
		},
		Trusted: append([]string(nil), cfg.Trusted...),
	}

	if !cfg.IsGuardEnabled() {
		view.Guard = "off"
	}

	// Secret handling mapping
	view.Secrets["Default"] = string(cfg.Secrets.Mode)

	// Built-in secret rules
	for _, p := range policy.BuiltInSecretPatterns {
		view.Secrets[p] = string(cfg.Secrets.Mode)
	}

	// Exceptions
	for _, a := range cfg.Exceptions.Allow {
		view.Secrets[a] = "allow"
	}
	for _, d := range cfg.Exceptions.Deny {
		view.Secrets[d] = "deny"
	}

	// Registered vault keys
	if vault.GlobalVault != nil {
		if keys, err := vault.GlobalVault.List(); err == nil {
			for _, k := range keys {
				view.Environment[k] = "fake"
			}
		}
	}

	return cfg, configPath, view, nil
}

func runConfigShow(progName string, args []string) error {
	isJSON := false
	for _, arg := range args {
		if arg == "--json" || arg == "-j" {
			isJSON = true
			break
		}
	}

	cwd, _ := os.Getwd()
	_, _, view, err := getEffectivePolicy(cwd)
	if err != nil {
		return err
	}

	if isJSON {
		data, err := json.MarshalIndent(view, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}

	fmt.Println("SecretHarbor Configuration")
	fmt.Println(stringsRepeat("─", 45))
	fmt.Printf("Protection: %s\n\n", view.Protection)

	fmt.Println("Secrets:")
	fmt.Printf("  Default:       %s\n", view.Secrets["Default"])
	for k, v := range view.Secrets {
		if k == "Default" || strings.HasPrefix(k, "*.") || strings.Contains(k, "credentials") {
			continue
		}
		fmt.Printf("  %-14s %s\n", k+":", v)
	}
	fmt.Println()

	fmt.Println("Environment:")
	fmt.Printf("  Mode:          %s\n", view.Environment["Mode"])
	for k, v := range view.Environment {
		if k == "Mode" {
			continue
		}
		fmt.Printf("  %-14s → %s\n", k, v)
	}
	fmt.Println()

	fmt.Println("Network:")
	fmt.Printf("  Mode:          %s\n", view.Network.Mode)
	if len(view.Network.Allowed) > 0 {
		fmt.Println("  Allowed:")
		for _, a := range view.Network.Allowed {
			fmt.Printf("    • %s\n", a)
		}
	}
	fmt.Println()

	fmt.Println("IPC:")
	fmt.Printf("  Unix sockets:  %s\n", view.IPC.UnixSockets)
	fmt.Printf("  Abstract:      %s\n", view.IPC.AbstractSockets)
	fmt.Printf("  Docker:        %s\n\n", view.IPC.Docker)

	fmt.Println("Sandbox:")
	fmt.Printf("  Escape:        %s\n", view.Sandbox.Escape)

	if len(view.Trusted) > 0 {
		fmt.Println("\nTrusted Processes:")
		for _, t := range view.Trusted {
			fmt.Printf("  • %s\n", t)
		}
	}

	fmt.Println(stringsRepeat("─", 45))
	fmt.Println("\033[90mRead-only view. Raw secrets are never exposed.\033[0m")
	return nil
}

func runConfigSource(progName string, args []string) error {
	cwd, _ := os.Getwd()
	cfg, configPath, _, err := getEffectivePolicy(cwd)
	if err != nil {
		return err
	}

	relPath := configPath
	if r, err := filepath.Rel(cwd, configPath); err == nil {
		relPath = r
	}

	var sources []RuleSource

	// 1. Core file patterns
	sources = append(sources, RuleSource{
		Resource: ".env",
		Mode:     string(cfg.Secrets.Mode),
		Source:   fmt.Sprintf("built-in secret rule (preset: %s)", cfg.Protection),
	})

	for _, a := range cfg.Exceptions.Allow {
		sources = append(sources, RuleSource{
			Resource: a,
			Mode:     "allow",
			Source:   fmt.Sprintf("project %s (exceptions.allow)", relPath),
		})
	}

	for _, d := range cfg.Exceptions.Deny {
		sources = append(sources, RuleSource{
			Resource: d,
			Mode:     "deny",
			Source:   fmt.Sprintf("project %s (exceptions.deny)", relPath),
		})
	}

	// 2. Sensitive env vars
	sources = append(sources,
		RuleSource{
			Resource: "DATABASE_URL",
			Mode:     "fake",
			Source:   "built-in database credential pattern",
		},
		RuleSource{
			Resource: "SSH_AUTH_SOCK",
			Mode:     "stripped",
			Source:   "built-in privileged socket isolation",
		},
		RuleSource{
			Resource: "DOCKER_HOST",
			Mode:     "stripped",
			Source:   "built-in privileged socket isolation",
		},
	)

	// 3. Network domains
	for _, domain := range cfg.Network.Allow {
		sources = append(sources, RuleSource{
			Resource: domain,
			Mode:     "allow",
			Source:   fmt.Sprintf("project %s (network.allow)", relPath),
		})
	}

	fmt.Println("SecretHarbor Policy Provenance")
	fmt.Println(stringsRepeat("─", 50))
	for _, s := range sources {
		fmt.Printf("%s\n", s.Resource)
		fmt.Printf("  mode:   %s\n", s.Mode)
		fmt.Printf("  source: %s\n\n", s.Source)
	}
	return nil
}

func runConfigCheck(progName string, args []string) error {
	var cfg *policy.Config
	var path string
	var err error

	if len(args) > 0 && args[0] != "" {
		path = args[0]
		cfg, err = policy.LoadPolicyFromFile(path)
	} else {
		cwd, _ := os.Getwd()
		cfg, path, err = policy.LoadPolicy(cwd)
	}
	if err != nil {
		return fmt.Errorf("configuration check failed: %w", err)
	}

	fmt.Printf("\033[32m✓ Configuration is valid\033[0m (%s)\n", path)
	fmt.Printf("  Version:    %d\n", cfg.Version)
	fmt.Printf("  Protection: %s\n", cfg.Protection)
	fmt.Printf("  Secrets:    %s\n", cfg.Secrets.Mode)
	fmt.Printf("  Network:    %s (%d allowed domains)\n", cfg.Network.Mode, len(cfg.Network.Allow))
	return nil
}

func runConfigEdit(progName string, args []string) error {
	// STRICT SECURITY BOUNDARY: Sandboxed agents must NEVER be allowed to run config edit
	if isSandboxedAgent() {
		return fmt.Errorf("Permission denied: SecretHarbor policy is human-controlled.")
	}

	cwd, _ := os.Getwd()
	configPath := policy.FindConfigFile(cwd)
	if configPath == "" {
		configPath = filepath.Join(cwd, policy.DefaultConfigFileName)
		_ = RunInit(progName, []string{configPath})
	}

	// Verify editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		for _, cand := range []string{"nano", "vim", "vi"} {
			if p, err := exec.LookPath(cand); err == nil {
				editor = p
				break
			}
		}
	}
	if editor == "" {
		return fmt.Errorf("no text editor found in $EDITOR, $VISUAL, or PATH (nano/vim/vi)")
	}

	// Read initial content to compute diff
	initialData, _ := os.ReadFile(configPath)

	// Launch trusted editor
	cmd := exec.Command(editor, configPath)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	// Read edited content
	editedData, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read edited policy: %w", err)
	}

	// Validate syntax before accepting
	var tempCfg policy.Config
	if err := yaml.Unmarshal(editedData, &tempCfg); err != nil {
		// Revert to initial atomically preserving mode
		_ = policy.AtomicWriteFile(configPath, initialData, 0600)
		return fmt.Errorf("invalid YAML syntax: %w (reverted changes)", err)
	}
	if err := policy.ValidatePolicy(&tempCfg); err != nil {
		_ = policy.AtomicWriteFile(configPath, initialData, 0600)
		return fmt.Errorf("invalid policy: %w (reverted changes)", err)
	}

	if bytes.Equal(initialData, editedData) {
		fmt.Println("No policy changes made.")
		return nil
	}

	// Show change summary
	fmt.Printf("\n\033[32m✓ Policy updated successfully\033[0m (%s)\n", configPath)
	fmt.Println("Active agent sessions will need to be restarted to inherit new enforcement rules.")
	return nil
}

func runConfigDiff(progName string, args []string) error {
	cwd, _ := os.Getwd()
	cfg, path, err := policy.LoadPolicy(cwd)
	if err != nil {
		return err
	}

	// Compare with standard base preset
	stdCfg := &policy.Config{
		Version:    1,
		Protection: policy.ProtectionStandard,
	}
	policy.ApplyPresets(stdCfg)

	fmt.Printf("SecretHarbor Policy Customizations (%s vs standard preset)\n", filepath.Base(path))
	fmt.Println(stringsRepeat("─", 50))

	hasDiff := false
	if cfg.Protection != stdCfg.Protection {
		fmt.Printf("- protection: %s\n+ protection: %s\n", stdCfg.Protection, cfg.Protection)
		hasDiff = true
	}
	if cfg.Secrets.Mode != stdCfg.Secrets.Mode {
		fmt.Printf("- secrets.mode: %s\n+ secrets.mode: %s\n", stdCfg.Secrets.Mode, cfg.Secrets.Mode)
		hasDiff = true
	}

	for _, a := range cfg.Exceptions.Allow {
		fmt.Printf("+ exceptions.allow: %s\n", a)
		hasDiff = true
	}
	for _, d := range cfg.Exceptions.Deny {
		fmt.Printf("+ exceptions.deny: %s\n", d)
		hasDiff = true
	}

	for _, d := range cfg.Network.Allow {
		found := false
		for _, stdD := range stdCfg.Network.Allow {
			if d == stdD {
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("+ network.allow: %s\n", d)
			hasDiff = true
		}
	}

	if !hasDiff {
		fmt.Println("Project policy matches standard preset exactly.")
	}

	return nil
}

func promptConfirm(prompt string) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	text = strings.ToLower(strings.TrimSpace(text))
	return text == "y" || text == "yes"
}

func runConfigGet(progName string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: %s config get <key>", progName)
	}
	key := strings.ToLower(strings.TrimSpace(args[0]))

	cwd, _ := os.Getwd()
	cfg, _, err := policy.LoadPolicy(cwd)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	switch key {
	case "version":
		fmt.Printf("%d\n", cfg.Version)
	case "protection":
		fmt.Printf("%s\n", cfg.Protection)
	case "guard":
		if cfg.IsGuardEnabled() {
			fmt.Println("on")
		} else {
			fmt.Println("off")
		}
	case "secrets.mode", "secrets":
		fmt.Printf("%s\n", cfg.Secrets.Mode)
	case "network.mode", "network":
		fmt.Printf("%s\n", cfg.Network.Mode)
	case "network.allow":
		for _, a := range cfg.Network.Allow {
			fmt.Printf("  • %s\n", a)
		}
	case "environment.mode", "environment":
		fmt.Printf("%s\n", cfg.Environment.Mode)
	case "ipc.docker.mode", "docker":
		fmt.Printf("%s\n", cfg.IPC.Docker.Mode)
	case "ipc.unix_sockets.mode", "unix_sockets":
		fmt.Printf("%s\n", cfg.IPC.UnixSockets.Mode)
	case "sandbox.escape", "escape":
		fmt.Printf("%s\n", cfg.Sandbox.Escape)
	case "trusted":
		for _, t := range cfg.Trusted {
			fmt.Printf("  • %s\n", t)
		}
	default:
		return fmt.Errorf("unknown configuration key %q. Supported keys: protection, guard, secrets.mode, network.mode, network.allow, environment.mode, ipc.docker.mode, sandbox.escape, trusted", key)
	}
	return nil
}

func runConfigSet(progName string, args []string) error {
	// STRICT SECURITY BOUNDARY: Sandboxed agents must NEVER be allowed to run config set
	if isSandboxedAgent() {
		return fmt.Errorf("Permission denied: SecretHarbor policy is human-controlled.")
	}

	if len(args) < 2 {
		return fmt.Errorf("usage: %s config set <key> <value>", progName)
	}
	key := strings.ToLower(strings.TrimSpace(args[0]))
	val := strings.TrimSpace(args[1])

	cwd, _ := os.Getwd()
	cfg, configPath, err := policy.LoadPolicy(cwd)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	if configPath == "" {
		configPath = filepath.Join(cwd, policy.DefaultConfigFileName)
	}

	switch key {
	case "protection":
		val = strings.ToLower(val)
		switch policy.ProtectionLevel(val) {
		case policy.ProtectionPermissive, policy.ProtectionStandard, policy.ProtectionStrict:
			cfg.Protection = policy.ProtectionLevel(val)
			policy.ApplyPresets(cfg)
		default:
			return fmt.Errorf("invalid protection level %q (must be standard, strict, or permissive)", val)
		}
	case "guard":
		val = strings.ToLower(val)
		if val == "on" || val == "true" || val == "1" {
			cfg.Guard = "on"
		} else if val == "off" || val == "false" || val == "0" {
			cfg.Guard = "off"
		} else {
			return fmt.Errorf("invalid guard value %q (must be on or off)", val)
		}
	case "secrets.mode", "secrets":
		val = strings.ToLower(val)
		switch policy.SecretMode(val) {
		case policy.SecretModeFake, policy.SecretModeDeny, policy.SecretModeAllow:
			cfg.Secrets.Mode = policy.SecretMode(val)
		default:
			return fmt.Errorf("invalid secrets mode %q (must be fake, deny, or allow)", val)
		}
	case "network.mode", "network":
		val = strings.ToLower(val)
		switch policy.NetworkMode(val) {
		case policy.NetworkModeRestricted, policy.NetworkModeDeny, policy.NetworkModeAllow:
			cfg.Network.Mode = policy.NetworkMode(val)
		default:
			return fmt.Errorf("invalid network mode %q (must be restricted, deny, or allow)", val)
		}
	case "environment.mode", "environment":
		val = strings.ToLower(val)
		switch policy.EnvMode(val) {
		case policy.EnvModeSanitize, policy.EnvModeStrict, policy.EnvModePass:
			cfg.Environment.Mode = policy.EnvMode(val)
		default:
			return fmt.Errorf("invalid environment mode %q (must be sanitize, strict, or pass)", val)
		}
	case "ipc.docker.mode", "docker":
		val = strings.ToLower(val)
		switch policy.DockerIPCMode(val) {
		case policy.DockerIPCModeApproval, policy.DockerIPCModeDeny, policy.DockerIPCModeAllow:
			cfg.IPC.Docker.Mode = policy.DockerIPCMode(val)
		default:
			return fmt.Errorf("invalid docker IPC mode %q (must be approval, deny, or allow)", val)
		}
	case "sandbox.escape", "escape":
		val = strings.ToLower(val)
		switch policy.SandboxEscapeMode(val) {
		case policy.SandboxEscapeDeny:
			cfg.Sandbox.Escape = policy.SandboxEscapeMode(val)
		default:
			return fmt.Errorf("invalid sandbox escape mode %q (only %q is supported)", val, policy.SandboxEscapeDeny)
		}
	default:
		return fmt.Errorf("unknown or unsupported configuration key %q for set", key)
	}

	if err := policy.ValidatePolicy(cfg); err != nil {
		return fmt.Errorf("resulting configuration is invalid: %w", err)
	}

	if err := policy.SavePolicyToFile(configPath, cfg); err != nil {
		return fmt.Errorf("failed to save policy: %w", err)
	}

	fmt.Printf("\033[32m✓ Set %s = %s\033[0m (%s)\n", key, val, configPath)
	return nil
}
