package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultConfigFileName is the standard configuration file name.
const (
	DefaultConfigFileName = "secretharbor.yaml"
	AltConfigFileName     = ".secretharbor.yaml"
	GlobalPolicyDir       = ".secretharbor"
	GlobalPolicyFileName  = "policy.yaml"
)

// LoadPolicy locates and parses the policy configuration.
// It searches the given directory and parents for secretharbor.yaml,
// falling back to ~/.secretharbor/policy.yaml, or returns the default preset.
func LoadPolicy(startDir string) (*Config, string, error) {
	configPath := FindConfigFile(startDir)
	if configPath == "" {
		// Use default standard preset if no file found
		cfg := &Config{
			Version:    1,
			Protection: ProtectionStandard,
		}
		ApplyPresets(cfg)
		return cfg, "", nil
	}

	cfg, err := LoadPolicyFromFile(configPath)
	if err != nil {
		return nil, configPath, err
	}

	return cfg, configPath, nil
}

// LoadPolicyFromFile reads and validates a specific policy file.
func LoadPolicyFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML in %s: %w", path, err)
	}

	ApplyPresets(&cfg)

	if err := ValidatePolicy(&cfg); err != nil {
		return nil, fmt.Errorf("invalid policy %s: %w", path, err)
	}

	return &cfg, nil
}

// FindConfigFile looks for secretharbor.yaml in dir and parents, then ~/.secretharbor/policy.yaml.
func FindConfigFile(dir string) string {
	if dir == "" {
		var err error
		dir, err = os.Getwd()
		if err != nil {
			dir = "."
		}
	}

	absDir, err := filepath.Abs(dir)
	if err == nil {
		curr := absDir
		for {
			cand1 := filepath.Join(curr, DefaultConfigFileName)
			if fileExists(cand1) {
				return cand1
			}
			cand2 := filepath.Join(curr, AltConfigFileName)
			if fileExists(cand2) {
				return cand2
			}

			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}
	}

	// Fallback to ~/.secretharbor/policy.yaml
	if home, err := os.UserHomeDir(); err == nil {
		globalPath := filepath.Join(home, GlobalPolicyDir, GlobalPolicyFileName)
		if fileExists(globalPath) {
			return globalPath
		}
	}

	return ""
}

// ValidatePolicy performs semantic validation of the policy.
func ValidatePolicy(cfg *Config) error {
	if cfg.Version != 1 {
		return fmt.Errorf("unsupported policy version: %d (expected 1)", cfg.Version)
	}

	switch cfg.Protection {
	case ProtectionPermissive, ProtectionStandard, ProtectionStrict, ProtectionCustom:
	default:
		return fmt.Errorf("unknown protection level: %q", cfg.Protection)
	}

	switch cfg.Secrets.Mode {
	case SecretModeAllow, SecretModeFake, SecretModeDeny:
	default:
		return fmt.Errorf("invalid secrets mode: %q", cfg.Secrets.Mode)
	}

	// Check for conflicting allow and deny exceptions
	denyMap := make(map[string]bool)
	for _, d := range cfg.Exceptions.Deny {
		denyMap[d] = true
	}
	for _, a := range cfg.Exceptions.Allow {
		if denyMap[a] {
			return fmt.Errorf("conflicting exception rule for path: %q is in both allow and deny", a)
		}
	}

	// Validate environment configuration
	if cfg.Environment.Mode != "" {
		switch cfg.Environment.Mode {
		case EnvModeSanitize, EnvModePass, EnvModeStrict:
		default:
			return fmt.Errorf("invalid environment mode: %q", cfg.Environment.Mode)
		}
	}

	envDenyMap := make(map[string]bool)
	for _, d := range cfg.Environment.Deny {
		d = strings.TrimSpace(d)
		if d == "" {
			return fmt.Errorf("invalid environment deny variable: empty name")
		}
		envDenyMap[d] = true
	}
	for _, a := range cfg.Environment.Allow {
		a = strings.TrimSpace(a)
		if a == "" {
			return fmt.Errorf("invalid environment allow variable: empty name")
		}
		if envDenyMap[a] {
			return fmt.Errorf("conflicting environment variable: %q is in both allow and deny", a)
		}
	}
	for _, f := range cfg.Environment.Fake {
		f = strings.TrimSpace(f)
		if f == "" {
			return fmt.Errorf("invalid environment fake variable: empty name")
		}
		if envDenyMap[f] {
			return fmt.Errorf("conflicting environment variable: %q is in both fake and deny", f)
		}
	}

	// Validate network configuration
	if cfg.Network.Mode != "" {
		switch cfg.Network.Mode {
		case NetworkModeAllow, NetworkModeRestricted, NetworkModeDeny:
		default:
			return fmt.Errorf("invalid network mode: %q", cfg.Network.Mode)
		}
	}

	netDenyMap := make(map[string]bool)
	for _, d := range cfg.Network.Deny {
		d = strings.TrimSpace(d)
		if d == "" {
			return fmt.Errorf("invalid network deny domain: empty domain")
		}
		netDenyMap[d] = true
	}
	for _, a := range cfg.Network.Allow {
		a = strings.TrimSpace(a)
		if a == "" {
			return fmt.Errorf("invalid network allow domain: empty domain")
		}
		if netDenyMap[a] {
			return fmt.Errorf("conflicting network domain: %q is in both allow and deny", a)
		}
	}

	// Validate IPC configuration
	if cfg.IPC.UnixSockets.Mode != "" {
		switch cfg.IPC.UnixSockets.Mode {
		case IPCModeAllow, IPCModeRestricted, IPCModeDeny:
		default:
			return fmt.Errorf("invalid unix_sockets mode: %q", cfg.IPC.UnixSockets.Mode)
		}
	}
	if cfg.IPC.AbstractSockets.Mode != "" {
		switch cfg.IPC.AbstractSockets.Mode {
		case IPCModeAllow, IPCModeRestricted, IPCModeDeny:
		default:
			return fmt.Errorf("invalid abstract_sockets mode: %q", cfg.IPC.AbstractSockets.Mode)
		}
	}
	if cfg.IPC.Docker.Mode != "" {
		switch cfg.IPC.Docker.Mode {
		case DockerIPCModeDeny, DockerIPCModeApproval, DockerIPCModeAllow:
		default:
			return fmt.Errorf("invalid docker mode: %q", cfg.IPC.Docker.Mode)
		}
	}

	// Validate Sandbox configuration
	if cfg.Sandbox.Escape != "" {
		switch cfg.Sandbox.Escape {
		case SandboxEscapeDeny:
		case SandboxEscapeAllowOnce:
			return fmt.Errorf("sandbox.escape: %q is not implemented; use %q", cfg.Sandbox.Escape, SandboxEscapeDeny)
		default:
			return fmt.Errorf("invalid sandbox escape mode: %q", cfg.Sandbox.Escape)
		}
	}

	if len(cfg.IPC.Docker.AllowedContainers) > 0 {
		return fmt.Errorf("ipc.docker.allowed_containers is not supported; remove it or use ipc.docker.mode")
	}

	// Validate secret capability rules
	for _, r := range cfg.Rules {
		if strings.TrimSpace(r.Secret) == "" {
			return fmt.Errorf("invalid rule: secret name cannot be empty")
		}
		if r.Read != "" {
			switch r.Read {
			case SecretModeAllow, SecretModeFake, SecretModeDeny:
			default:
				return fmt.Errorf("invalid rule read mode for %s: %q", r.Secret, r.Read)
			}
		}
	}

	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// AtomicWriteFile writes data to a temporary file in the same directory, syncs to disk,
// preserves existing file permissions (or defaultPerm if creating anew), and renames atomically.
func AtomicWriteFile(path string, data []byte, defaultPerm os.FileMode) error {
	perm := defaultPerm
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm()
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmpFile.Name()
	defer os.Remove(tmpName)

	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}

	if err := tmpFile.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}

// SavePolicyToFile writes the given configuration back to disk in YAML format atomically with 0600.
func SavePolicyToFile(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to encode policy YAML: %w", err)
	}
	return AtomicWriteFile(path, data, 0600)
}
