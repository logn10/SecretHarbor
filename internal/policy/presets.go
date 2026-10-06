package policy

// BuiltInSecretPatterns lists default filename/path patterns considered sensitive.
var BuiltInSecretPatterns = []string{
	".env",
	".env.*",
	"*.pem",
	"*.key",
	"*.p12",
	"*.pfx",
	"credentials.json",
	"credentials.yml",
	"credentials.yaml",
	".aws/credentials",
	".aws/config",
	".ssh/*",
	".gnupg/*",
	"id_rsa*",
	"id_ed25519*",
}

// DefaultSafeEnvVars lists environment variables that are safe for agents to inherit.
var DefaultSafeEnvVars = []string{
	"HOME",
	"PATH",
	"SHELL",
	"PWD",
	"USER",
	"LANG",
	"LC_ALL",
	"LC_CTYPE",
	"TERM",
	"TMPDIR",
	"EDITOR",
	"COLORTERM",
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",
	"NODE_EXTRA_CA_CERTS",
	"REQUESTS_CA_BUNDLE",
	"CURL_CA_BUNDLE",
	"CARGO_HTTP_CAINFO",
	"GIT_SSL_CAINFO",
	"NO_PROXY",
	"no_proxy",
}

// PrivilegedIPCEmptyVars lists environment variables that expose privileged local services.
var PrivilegedIPCEmptyVars = []string{
	"SSH_AUTH_SOCK",
	"DOCKER_HOST",
	"CONTAINER_HOST",
	"DOCKER_CONTEXT",
	"KUBECONFIG",
	"DOCKER_CERT_PATH",
	"DOCKER_TLS_VERIFY",
	"MINIKUBE_ACTIVE_DOCKERD",
}

// DefaultSecretEnvVarNames lists common environment variables containing credentials.
var DefaultSecretEnvVarNames = []string{
	"AWS_SECRET_ACCESS_KEY",
	"AWS_SESSION_TOKEN",
	"AWS_ACCESS_KEY_ID",
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
	"GEMINI_API_KEY",
	"STRIPE_SECRET_KEY",
	"STRIPE_API_KEY",
	"DATABASE_URL",
	"DB_PASSWORD",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"NPM_TOKEN",
	"SLACK_BOT_TOKEN",
	"SENDGRID_API_KEY",
	"PRIVATE_KEY",
	"SECRET_KEY",
	"JWT_SECRET",
}

// ApplyPresets applies defaults for standard, strict, or permissive configurations.
func ApplyPresets(cfg *Config) {
	if cfg.Version == 0 {
		cfg.Version = 1
	}

	if cfg.Protection == "" {
		cfg.Protection = ProtectionStandard
	}

	switch cfg.Protection {
	case ProtectionStrict:
		applyStrictPreset(cfg)
	case ProtectionPermissive:
		applyPermissivePreset(cfg)
	case ProtectionStandard:
		fallthrough
	default:
		applyStandardPreset(cfg)
	}
}

func applyStandardPreset(cfg *Config) {
	if cfg.Secrets.Mode == "" {
		cfg.Secrets.Mode = SecretModeFake
	}
	if cfg.Environment.Mode == "" {
		cfg.Environment.Mode = EnvModeSanitize
	}
	if len(cfg.Environment.Allow) == 0 {
		cfg.Environment.Allow = append([]string(nil), DefaultSafeEnvVars...)
	}
	if len(cfg.Environment.Fake) == 0 {
		cfg.Environment.Fake = []string{
			"DATABASE_URL",
			"STRIPE_SECRET_KEY",
			"OPENAI_API_KEY",
			"ANTHROPIC_API_KEY",
			"GEMINI_API_KEY",
			"GITHUB_TOKEN",
		}
	}
	if len(cfg.Environment.Deny) == 0 {
		cfg.Environment.Deny = append([]string(nil), PrivilegedIPCEmptyVars...)
		cfg.Environment.Deny = append(cfg.Environment.Deny, "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
	}
	if cfg.Network.Mode == "" {
		cfg.Network.Mode = NetworkModeAllow
	}
	if len(cfg.Network.Allow) == 0 {
		cfg.Network.Allow = []string{
			"github.com",
			"registry.npmjs.org",
			"proxy.golang.org",
			"crates.io",
			"pypi.org",
			"api.openai.com",
			"api.anthropic.com",
			"generativelanguage.googleapis.com",
			"opencode.ai",
			"openrouter.ai",
			"localhost",
			"127.0.0.1",
		}
	}
	if cfg.IPC.UnixSockets.Mode == "" {
		cfg.IPC.UnixSockets.Mode = IPCModeDeny
	}
	if cfg.IPC.AbstractSockets.Mode == "" {
		cfg.IPC.AbstractSockets.Mode = IPCModeDeny
	}
	if cfg.IPC.Docker.Mode == "" {
		cfg.IPC.Docker.Mode = DockerIPCModeApproval
	}
	if cfg.Sandbox.Escape == "" {
		cfg.Sandbox.Escape = SandboxEscapeDeny
	}
}

func applyStrictPreset(cfg *Config) {
	if cfg.Secrets.Mode == "" {
		cfg.Secrets.Mode = SecretModeDeny
	}
	if cfg.Environment.Mode == "" {
		cfg.Environment.Mode = EnvModeStrict
	}
	if len(cfg.Environment.Allow) == 0 {
		cfg.Environment.Allow = []string{"PATH", "HOME", "USER", "TERM"}
	}
	if len(cfg.Environment.Deny) == 0 {
		cfg.Environment.Deny = append([]string(nil), PrivilegedIPCEmptyVars...)
		cfg.Environment.Deny = append(cfg.Environment.Deny, DefaultSecretEnvVarNames...)
	}
	if cfg.Network.Mode == "" {
		cfg.Network.Mode = NetworkModeDeny
	}
	if cfg.IPC.UnixSockets.Mode == "" {
		cfg.IPC.UnixSockets.Mode = IPCModeDeny
	}
	if cfg.IPC.AbstractSockets.Mode == "" {
		cfg.IPC.AbstractSockets.Mode = IPCModeDeny
	}
	if cfg.IPC.Docker.Mode == "" {
		cfg.IPC.Docker.Mode = DockerIPCModeDeny
	}
	if cfg.Sandbox.Escape == "" {
		cfg.Sandbox.Escape = SandboxEscapeDeny
	}
}

func applyPermissivePreset(cfg *Config) {
	if cfg.Secrets.Mode == "" {
		cfg.Secrets.Mode = SecretModeFake
	}
	if cfg.Environment.Mode == "" {
		cfg.Environment.Mode = EnvModeSanitize
	}
	if len(cfg.Environment.Allow) == 0 {
		cfg.Environment.Allow = append([]string(nil), DefaultSafeEnvVars...)
	}
	if len(cfg.Environment.Deny) == 0 {
		cfg.Environment.Deny = append([]string(nil), PrivilegedIPCEmptyVars...)
	}
	if cfg.Network.Mode == "" {
		cfg.Network.Mode = NetworkModeAllow
	}
	if cfg.IPC.UnixSockets.Mode == "" {
		cfg.IPC.UnixSockets.Mode = IPCModeRestricted
	}
	if cfg.IPC.AbstractSockets.Mode == "" {
		cfg.IPC.AbstractSockets.Mode = IPCModeRestricted
	}
	if cfg.IPC.Docker.Mode == "" {
		cfg.IPC.Docker.Mode = DockerIPCModeApproval
	}
	if cfg.Sandbox.Escape == "" {
		cfg.Sandbox.Escape = SandboxEscapeDeny
	}
}
