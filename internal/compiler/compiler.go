package compiler

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/secretharbor/secretharbor/internal/policy"
)

// CompiledPlan represents the immutable OS-level enforcement specification.
type CompiledPlan struct {
	Policy     *policy.Config
	ConfigPath string
	ProjectDir string
	HomeDir    string

	Filesystem  FilesystemPlan
	Environment EnvironmentPlan
	Network     NetworkPlan
	IPC         IPCPlan
	Process     ProcessPlan
	Runtime     RuntimePlan
}

// FilesystemPlan holds compiled path-level rules.
type FilesystemPlan struct {
	Mode               policy.SecretMode
	DeniedPaths        []string          // Absolute paths denied access
	FakeFiles          map[string]string // Real absolute path -> Fake synthetic path
	AllowedPaths       []string          // Absolute paths explicitly allowed
	SelfProtectedPaths []string          // Control-plane paths protected from agent
}

// EnvironmentPlan holds compiled environment variables.
type EnvironmentPlan struct {
	Mode         policy.EnvMode
	AllowList    []string
	DenyList     []string
	FakeVars     map[string]string // Variable name -> Fake value
	StrippedVars []string          // Variables purged from parent env
	FinalEnv     []string          // KEY=VALUE pairs for child process
	Effective    policy.EnvConfig  // Environment config with rules[].read merged in
}

// NetworkPlan holds compiled network isolation rules.
type NetworkPlan struct {
	Mode           policy.NetworkMode
	AllowedDomains []string
	DeniedDomains  []string
	ProxyPort      int
	ProxyRequired  bool
}

// IPCPlan holds compiled IPC controls.
type IPCPlan struct {
	DenyUnixSockets         bool
	DenyAbstractSockets     bool
	BlockedSocketPaths      []string
	DockerMode              policy.DockerIPCMode
	DockerAllowedContainers []string
}

// ProcessPlan holds process-level hardening controls.
type ProcessPlan struct {
	SetDumpableZero    bool
	CloseUnexpectedFDs bool
	DenySandboxEscape  bool
	TrustedProcesses   []string
}

// RuntimePlan holds compiled runtime injection permissions.
type RuntimePlan struct {
	AllowedSecrets []string
}

// Compile translates a high-level policy.Config into an immutable execution plan.
func Compile(cfg *policy.Config, configPath string, projectDir string) (*CompiledPlan, error) {
	if cfg == nil {
		cfg = &policy.Config{
			Version:    1,
			Protection: policy.ProtectionStandard,
		}
		policy.ApplyPresets(cfg)
	}

	if projectDir == "" {
		var err error
		projectDir, err = os.Getwd()
		if err != nil {
			projectDir = "."
		}
	}
	absProjectDir, err := filepath.Abs(projectDir)
	if err == nil {
		projectDir = absProjectDir
	}

	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		homeDir = os.Getenv("HOME")
	}
	if homeDir == "" {
		return nil, fmt.Errorf("cannot determine home directory for security policy compilation; refusing to compile an unsafe enforcement plan")
	}
	if realHome, err := filepath.EvalSymlinks(homeDir); err == nil {
		homeDir = realHome
	}
	homeDir = filepath.Clean(homeDir)

	plan := &CompiledPlan{
		Policy:     cfg,
		ConfigPath: configPath,
		ProjectDir: projectDir,
		HomeDir:    homeDir,
		Filesystem: FilesystemPlan{
			Mode:      cfg.Secrets.Mode,
			FakeFiles: make(map[string]string),
		},
		Environment: EnvironmentPlan{
			Mode:     cfg.Environment.Mode,
			FakeVars: make(map[string]string),
		},
		Network: NetworkPlan{
			Mode:           cfg.Network.Mode,
			AllowedDomains: append([]string(nil), cfg.Network.Allow...),
		},
		IPC: IPCPlan{
			DenyUnixSockets:         cfg.IPC.UnixSockets.Mode == policy.IPCModeDeny,
			DenyAbstractSockets:     cfg.IPC.AbstractSockets.Mode == policy.IPCModeDeny,
			DockerMode:              cfg.IPC.Docker.Mode,
			DockerAllowedContainers: append([]string(nil), cfg.IPC.Docker.AllowedContainers...),
		},
		Process: ProcessPlan{
			SetDumpableZero:    true,
			CloseUnexpectedFDs: true,
			DenySandboxEscape:  cfg.Sandbox.Escape != policy.SandboxEscapeAllowOnce,
			TrustedProcesses:   append([]string(nil), cfg.Trusted...),
		},
		Runtime: RuntimePlan{
			AllowedSecrets: append([]string(nil), cfg.Runtime.Allow...),
		},
	}

	// 1. Compile Self-Protection paths with symlink resolution (Section 22 & 5.1)
	rawControlPaths := []string{
		filepath.Join(homeDir, policy.GlobalPolicyDir),
		configPath,
	}
	if execPath, err := os.Executable(); err == nil {
		rawControlPaths = append(rawControlPaths, execPath)
		execDir := filepath.Dir(execPath)
		rawControlPaths = append(rawControlPaths,
			filepath.Join(execDir, "shb"),
			filepath.Join(execDir, "secretharbor"),
		)
	}

	seenControlPaths := make(map[string]bool)
	for _, p := range rawControlPaths {
		if p == "" {
			continue
		}
		cleanP := filepath.Clean(p)
		if !seenControlPaths[cleanP] {
			seenControlPaths[cleanP] = true
			plan.Filesystem.SelfProtectedPaths = append(plan.Filesystem.SelfProtectedPaths, cleanP)
		}
		if evalP, err := filepath.EvalSymlinks(cleanP); err == nil {
			evalClean := filepath.Clean(evalP)
			if !seenControlPaths[evalClean] {
				seenControlPaths[evalClean] = true
				plan.Filesystem.SelfProtectedPaths = append(plan.Filesystem.SelfProtectedPaths, evalClean)
			}
		}
	}

	// 2. Compile Filesystem Allowed Paths
	for _, a := range cfg.Exceptions.Allow {
		plan.Filesystem.AllowedPaths = append(plan.Filesystem.AllowedPaths, resolvePath(a, projectDir, homeDir))
	}

	// 3. Compile Filesystem Denied Paths
	for _, d := range cfg.Exceptions.Deny {
		plan.Filesystem.DeniedPaths = append(plan.Filesystem.DeniedPaths, resolvePath(d, projectDir, homeDir))
	}
	plan.Filesystem.DeniedPaths = append(plan.Filesystem.DeniedPaths,
		filepath.Join(homeDir, ".secretharbor", "vault"),
		"/run/secrets",
		filepath.Join(homeDir, ".docker/config.json"),
		// Cloud and developer credential stores that must never reach the agent (BUG-014).
		filepath.Join(homeDir, ".config", "gcloud"),
		filepath.Join(homeDir, ".azure"),
		filepath.Join(homeDir, ".netrc"),
		filepath.Join(homeDir, ".npmrc"),
		filepath.Join(homeDir, ".pypirc"),
		filepath.Join(homeDir, ".git-credentials"),
		filepath.Join(homeDir, ".kube", "config"),
	)

	// 4. Compile Secret Rules (rules[].read is enforced for both files and environment variables)
	effectiveEnv := policy.EnvConfig{
		Mode:  cfg.Environment.Mode,
		Allow: append([]string(nil), cfg.Environment.Allow...),
		Fake:  append([]string(nil), cfg.Environment.Fake...),
		Deny:  append([]string(nil), cfg.Environment.Deny...),
	}
	for _, rule := range cfg.Rules {
		if rule.Secret == "" {
			continue
		}
		if isPathRule(rule.Secret) {
			switch rule.Read {
			case policy.SecretModeDeny:
				plan.Filesystem.DeniedPaths = append(plan.Filesystem.DeniedPaths, resolvePath(rule.Secret, projectDir, homeDir))
			case policy.SecretModeAllow:
				plan.Filesystem.AllowedPaths = append(plan.Filesystem.AllowedPaths, resolvePath(rule.Secret, projectDir, homeDir))
			}
			continue
		}
		switch rule.Read {
		case policy.SecretModeDeny:
			plan.Environment.DenyList = appendUniqueString(plan.Environment.DenyList, rule.Secret)
			effectiveEnv.Deny = appendUniqueString(effectiveEnv.Deny, rule.Secret)
		case policy.SecretModeAllow:
			plan.Environment.AllowList = appendUniqueString(plan.Environment.AllowList, rule.Secret)
			effectiveEnv.Allow = appendUniqueString(effectiveEnv.Allow, rule.Secret)
		case policy.SecretModeFake:
			effectiveEnv.Fake = appendUniqueString(effectiveEnv.Fake, rule.Secret)
		}
	}
	plan.Environment.Effective = effectiveEnv

	// 5. Compile IPC Blocked Socket Paths
	if cfg.IPC.Docker.Mode == policy.DockerIPCModeDeny || cfg.IPC.Docker.Mode == policy.DockerIPCModeApproval {
		plan.IPC.BlockedSocketPaths = append(plan.IPC.BlockedSocketPaths,
			"/var/run/docker.sock",
			filepath.Join(homeDir, ".docker/run/docker.sock"),
			"/run/podman/podman.sock",
			"/var/run/containerd/containerd.sock",
		)
	}
	if sshSock := os.Getenv("SSH_AUTH_SOCK"); sshSock != "" {
		plan.IPC.BlockedSocketPaths = append(plan.IPC.BlockedSocketPaths, sshSock)
	}

	// 6. Network proxy requirements
	plan.Network.DeniedDomains = cfg.Network.Deny
	if plan.Network.Mode == policy.NetworkModeRestricted || plan.Network.Mode == policy.NetworkModeDeny || len(plan.Network.DeniedDomains) > 0 {
		plan.Network.ProxyRequired = true
	}

	return plan, nil
}

func isPathRule(secret string) bool {
	return strings.Contains(secret, "/") || strings.Contains(secret, ".")
}

func appendUniqueString(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

func resolvePath(p, projectDir, homeDir string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(homeDir, p[2:])
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(projectDir, p)
}
