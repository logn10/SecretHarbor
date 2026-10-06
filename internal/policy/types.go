package policy

import "strings"

// ProtectionLevel defines the default security preset.
type ProtectionLevel string

const (
	ProtectionPermissive ProtectionLevel = "permissive"
	ProtectionStandard   ProtectionLevel = "standard"
	ProtectionStrict     ProtectionLevel = "strict"
	ProtectionCustom     ProtectionLevel = "custom"
)

// SecretMode defines how secrets are presented to the agent.
type SecretMode string

const (
	SecretModeAllow SecretMode = "allow"
	SecretModeFake  SecretMode = "fake"
	SecretModeDeny  SecretMode = "deny"
)

// Config represents the top-level secretharbor.yaml configuration.
type Config struct {
	Version     int              `yaml:"version" json:"version"`
	Guard       string           `yaml:"guard,omitempty" json:"guard,omitempty"` // "on" or "off" (default "on")
	Protection  ProtectionLevel  `yaml:"protection" json:"protection"`
	Secrets     SecretsConfig    `yaml:"secrets" json:"secrets"`
	Exceptions  ExceptionsConfig `yaml:"exceptions" json:"exceptions"`
	Environment EnvConfig        `yaml:"environment" json:"environment"`
	Network     NetworkConfig    `yaml:"network" json:"network"`
	IPC         IPCConfig        `yaml:"ipc" json:"ipc"`
	Runtime     RuntimeConfig    `yaml:"runtime" json:"runtime"`
	Rules       []SecretRule     `yaml:"rules" json:"rules"`
	Sandbox     SandboxConfig    `yaml:"sandbox" json:"sandbox"`
	Trusted     []string         `yaml:"trusted,omitempty" json:"trusted,omitempty"`
}

// IsGuardEnabled returns true unless explicitly set to "off" or "disabled".
func (c *Config) IsGuardEnabled() bool {
	if c == nil {
		return true
	}
	g := strings.ToLower(strings.TrimSpace(c.Guard))
	return g != "off" && g != "disabled"
}

// SecretsConfig controls default secret handling.
type SecretsConfig struct {
	Mode SecretMode `yaml:"mode" json:"mode"`
}

// ExceptionsConfig defines paths exempt from default secret rules.
type ExceptionsConfig struct {
	Allow []string `yaml:"allow" json:"allow"`
	Deny  []string `yaml:"deny" json:"deny"`
}

// EnvMode defines environment sanitization mode.
type EnvMode string

const (
	EnvModeSanitize EnvMode = "sanitize"
	EnvModePass     EnvMode = "pass"
	EnvModeStrict   EnvMode = "strict"
)

// EnvConfig configures environment variable security.
type EnvConfig struct {
	Mode  EnvMode  `yaml:"mode" json:"mode"`
	Allow []string `yaml:"allow" json:"allow"`
	Fake  []string `yaml:"fake" json:"fake"`
	Deny  []string `yaml:"deny" json:"deny"`
}

// NetworkMode defines outbound network permissions.
type NetworkMode string

const (
	NetworkModeAllow      NetworkMode = "allow"
	NetworkModeRestricted NetworkMode = "restricted"
	NetworkModeDeny       NetworkMode = "deny"
)

// NetworkConfig controls network egress and domain allowlists.
type NetworkConfig struct {
	Mode  NetworkMode `yaml:"mode" json:"mode"`
	Allow []string    `yaml:"allow" json:"allow"`
	Deny  []string    `yaml:"deny" json:"deny"`
}

// IPCMode defines IPC access permissions.
type IPCMode string

const (
	IPCModeAllow      IPCMode = "allow"
	IPCModeRestricted IPCMode = "restricted"
	IPCModeDeny       IPCMode = "deny"
)

// SocketPolicy controls Unix and abstract sockets.
type SocketPolicy struct {
	Mode IPCMode `yaml:"mode" json:"mode"`
}

// DockerIPCMode defines Docker daemon capability access modes.
type DockerIPCMode string

const (
	DockerIPCModeDeny     DockerIPCMode = "deny"     // Completely block Docker daemon socket and purge DOCKER_HOST
	DockerIPCModeApproval DockerIPCMode = "approval" // Capability-intercepted via proxy socket with out-of-band approval
	DockerIPCModeAllow    DockerIPCMode = "allow"    // Directly permit Docker daemon socket access
)

// DockerIPCPolicy controls access to the Docker daemon and container capabilities.
type DockerIPCPolicy struct {
	Mode              DockerIPCMode `yaml:"mode" json:"mode"`
	AllowedContainers []string      `yaml:"allowed_containers,omitempty" json:"allowed_containers,omitempty"`
}

// IPCConfig configures local IPC endpoints and domain sockets.
type IPCConfig struct {
	UnixSockets     SocketPolicy    `yaml:"unix_sockets" json:"unix_sockets"`
	AbstractSockets SocketPolicy    `yaml:"abstract_sockets" json:"abstract_sockets"`
	Docker          DockerIPCPolicy `yaml:"docker" json:"docker"`
}

// RuntimeConfig specifies runtime secret injection rules.
type RuntimeConfig struct {
	Allow []string `yaml:"allow" json:"allow"`
}

// SecretRule defines capability-scoped access for an individual secret.
type SecretRule struct {
	Secret string     `yaml:"secret" json:"secret"`
	Read   SecretMode `yaml:"read" json:"read"`
	Use    UseConfig  `yaml:"use" json:"use"`
}

// UseConfig controls capability-based secret brokering.
type UseConfig struct {
	Enabled bool     `yaml:"enabled" json:"enabled"`
	Hosts   []string `yaml:"hosts" json:"hosts"`
}

// SandboxEscapeMode controls whether unsandboxed execution is allowed.
type SandboxEscapeMode string

const (
	SandboxEscapeDeny      SandboxEscapeMode = "deny"
	SandboxEscapeAllowOnce SandboxEscapeMode = "allow_once"
)

// SandboxConfig configures sandbox boundaries and escape controls.
type SandboxConfig struct {
	Escape SandboxEscapeMode `yaml:"escape" json:"escape"`
}
