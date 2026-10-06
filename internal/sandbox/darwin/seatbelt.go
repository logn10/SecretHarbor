//go:build darwin

package darwin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/secretharbor/secretharbor/internal/agents"
	"github.com/secretharbor/secretharbor/internal/compiler"
	"github.com/secretharbor/secretharbor/internal/environment"
	"github.com/secretharbor/secretharbor/internal/fd"
	"github.com/secretharbor/secretharbor/internal/policy"
	"github.com/secretharbor/secretharbor/internal/secrets"
)

// DarwinSandbox enforces process isolation on macOS using Apple Seatbelt profiles.
type DarwinSandbox struct {
	plan            *compiler.CompiledPlan
	swapRecord      *secrets.SwapRecord
	virtualEnv      *secrets.VirtualizedEnvironment
	shadowWorkspace string
	profileData     string
	hasSeatbelt     bool
}

// NewSandbox initializes a macOS sandbox.
func NewSandbox(plan *compiler.CompiledPlan) (*DarwinSandbox, error) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		return nil, fmt.Errorf("macOS sandbox requirement not met: sandbox-exec binary not found in PATH: %w", err)
	}
	return &DarwinSandbox{
		plan:        plan,
		hasSeatbelt: true,
	}, nil
}

// Prepare scans sensitive paths, virtualizes secrets, and compiles the Seatbelt profile.
func (s *DarwinSandbox) Prepare(plan *compiler.CompiledPlan) error {
	s.plan = plan

	if plan.ProjectDir != "" {
		if _, err := os.Stat(plan.ProjectDir); err != nil {
			return fmt.Errorf("invalid project directory %s: %w", plan.ProjectDir, err)
		}
	}

	var allowExceptions, denyExceptions []string
	if plan.Policy != nil {
		allowExceptions = plan.Policy.Exceptions.Allow
		denyExceptions = plan.Policy.Exceptions.Deny
	}

	// 1. Secret virtualization.
	// Fake mode uses a shadow workspace: the real project (including .env) is never
	// modified, and only the sandboxed process tree sees synthetic fakes.
	if s.plan.Filesystem.Mode == policy.SecretModeFake {
		secretFiles, err := secrets.DetectSecretFilesInDir(
			plan.ProjectDir,
			allowExceptions,
			denyExceptions,
		)
		if err != nil {
			return fmt.Errorf("failed to detect secret files in project directory: %w", err)
		}

		if len(secretFiles) > 0 {
			ve, err := secrets.PrepareVirtualization(secretFiles)
			if err != nil {
				return fmt.Errorf("failed to prepare secret virtualization: %w", err)
			}
			ve.ProtectedPaths = plan.Filesystem.SelfProtectedPaths

			ws, err := ve.CreateShadowWorkspace(plan.ProjectDir)
			if err != nil {
				ve.Cleanup()
				return fmt.Errorf("failed to create shadow workspace: %w", err)
			}
			ve.WorkspaceDir = ws
			s.virtualEnv = ve
			s.shadowWorkspace = ws
			s.plan.Filesystem.FakeFiles = ve.FileMap

			// Deny the real secret paths (and any symlink targets) so absolute or
			// git-root-relative resolution cannot reach the real values.
			for _, f := range secretFiles {
				s.plan.Filesystem.DeniedPaths = append(s.plan.Filesystem.DeniedPaths, f)
				if resolved, rerr := filepath.EvalSymlinks(f); rerr == nil && resolved != f {
					s.plan.Filesystem.DeniedPaths = append(s.plan.Filesystem.DeniedPaths, resolved)
				}
			}
		}
	} else if s.plan.Filesystem.Mode == policy.SecretModeDeny {
		secretFiles, err := secrets.DetectSecretFilesInDir(
			plan.ProjectDir,
			allowExceptions,
			denyExceptions,
		)
		if err != nil {
			return fmt.Errorf("failed to detect secret files in project directory: %w", err)
		}
		for _, f := range secretFiles {
			s.plan.Filesystem.DeniedPaths = append(s.plan.Filesystem.DeniedPaths, f)
		}
	}

	// 2. Add common sensitive home paths if they exist
	home := plan.HomeDir
	sensitiveHomePaths := []string{
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".secretharbor", "vault"),
	}
	for _, p := range sensitiveHomePaths {
		if _, err := os.Stat(p); err == nil {
			s.plan.Filesystem.DeniedPaths = append(s.plan.Filesystem.DeniedPaths, p)
		}
	}

	// 3. Generate Seatbelt profile
	s.profileData = s.generateSeatbeltProfile()
	return nil
}

// Launch prepares sanitized environment, closes FDs, and executes the sandboxed command.
func (s *DarwinSandbox) Launch(command string, args []string, extraEnv []string) (*exec.Cmd, error) {
	// Clean environment
	rawEnv := append(os.Environ(), extraEnv...)
	envCfg := &s.plan.Environment.Effective
	if envCfg.Mode == "" && s.plan.Policy != nil {
		envCfg = &s.plan.Policy.Environment
	}
	res := environment.Sanitize(rawEnv, envCfg)
	finalEnv := append([]string(nil), res.FinalEnv...)

	// Auto-inject synthetic environment variables when in fake mode
	if s.plan.Filesystem.Mode == policy.SecretModeFake {
		var syntheticKVs []string
		denyEnvMap := make(map[string]bool)
		for _, d := range s.plan.Environment.Effective.Deny {
			denyEnvMap[d] = true
		}

		var synthVars map[string]string
		if s.virtualEnv != nil && len(s.virtualEnv.SyntheticValues) > 0 {
			synthVars = s.virtualEnv.SyntheticValues
		} else if s.swapRecord != nil && len(s.swapRecord.SyntheticValues) > 0 {
			synthVars = s.swapRecord.SyntheticValues
		} else {
			synthVars = secrets.ExtractEnvFromSwappedFiles(s.plan.ProjectDir)
		}

		for k, v := range synthVars {
			if !denyEnvMap[k] {
				syntheticKVs = append(syntheticKVs, k+"="+v)
			}
		}

		if len(syntheticKVs) > 0 {
			finalEnv = environment.MergeEnv(finalEnv, syntheticKVs)
		}
	}

	// If Docker IPC is approval-gated and SecretHarbor started a capability interceptor proxy,
	// ensure the proxy DOCKER_HOST is preserved in the sandboxed child environment.
	if s.plan.IPC.DockerMode == policy.DockerIPCModeApproval {
		for _, extra := range extraEnv {
			if strings.HasPrefix(extra, "DOCKER_HOST=unix:///tmp/shb-d-") {
				finalEnv = append(finalEnv, extra)
				break
			}
		}
	}

	// Clean file descriptors
	if err := fd.CloseUnexpectedFDs(nil); err != nil {
		return nil, fmt.Errorf("failed to sanitize file descriptors: %w", err)
	}

	finalArgs := args

	if !s.hasSeatbelt || s.profileData == "" {
		return nil, fmt.Errorf("cannot launch macOS sandboxed process: sandbox profile not prepared or sandbox-exec unavailable")
	}

	// Wrap with sandbox-exec
	fullArgs := append([]string{"-p", s.profileData, "--", command}, finalArgs...)
	cmd := exec.Command("sandbox-exec", fullArgs...)

	if s.shadowWorkspace != "" {
		cmd.Dir = s.shadowWorkspace
	} else {
		cmd.Dir = s.plan.ProjectDir
	}
	cmd.Env = finalEnv
	if agents.IsElectronOrChromiumApp(command) {
		cmd.Stdin = nil
	} else {
		cmd.Stdin = os.Stdin
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd, nil
}

// Cleanup tears down shadow virtualization files and restores swapped secret files.
func (s *DarwinSandbox) Cleanup() {
	if s.swapRecord != nil {
		_ = secrets.RestoreSwap(s.plan.ProjectDir)
		s.swapRecord = nil
	}
	if s.virtualEnv != nil {
		_ = s.virtualEnv.SyncBack(s.plan.ProjectDir)
		s.virtualEnv.Cleanup()
		s.virtualEnv = nil
	}
	s.shadowWorkspace = ""
}

func (s *DarwinSandbox) generateSeatbeltProfile() string {
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n\n")

	// 1. Self-protection: deny write to SecretHarbor control directory and binaries.
	// The control directory is fully hidden from the agent so it cannot read the
	// approval auth token or broker state (BUG-003).
	b.WriteString(";; SecretHarbor Control Plane Protection\n")
	for _, p := range s.plan.Filesystem.SelfProtectedPaths {
		if p == "" {
			continue
		}
		if filepath.Base(filepath.Clean(p)) == policy.GlobalPolicyDir {
			writePathRule(&b, "deny", "file-read* file-write*", p)
		} else {
			writePathRule(&b, "deny", "file-write*", p)
		}
	}

	// 2. Secret file enforcement
	if s.plan.Filesystem.Mode == policy.SecretModeDeny {
		b.WriteString("\n;; Protected Secret Patterns (Regex) - Deny Mode\n")
		b.WriteString("(deny file-read* file-write* (regex #\"(^|/)\\.env($|\\..*)\"))\n")
		b.WriteString("(deny file-read* file-write* (regex #\"\\.(pem|key|p12|pfx)$\"))\n")
		b.WriteString("(deny file-read* file-write* (regex #\"(^|/)credentials\\.(json|ya?ml)$\"))\n")
		b.WriteString("(deny file-read* file-write* (regex #\"(^|/)\\.(aws|ssh|gnupg)(/|$)\"))\n")

		// Deny detected project secret files
		for realPath := range s.plan.Filesystem.FakeFiles {
			writePathRule(&b, "deny", "file-read* file-write*", realPath)
		}
	} else if s.plan.Filesystem.Mode == policy.SecretModeFake {
		b.WriteString("\n;; Protected Secret Patterns - Fake Mode (In-Place Swapped)\n")
		// Deny sensitive host dirs outside project
		b.WriteString("(deny file-read* file-write* (regex #\"(^|/)\\.(aws|ssh|gnupg)(/|$)\"))\n")

		// Lock down SecretHarbor vault containing real backups
		home := s.plan.HomeDir
		if home != "" {
			writePathRule(&b, "deny", "file-read* file-write*", filepath.Join(home, ".secretharbor", "vault"))
		}

		// Prevent sandboxed process from deleting or renaming in-tree swapped fake secret files
		if s.swapRecord != nil {
			for _, sf := range s.swapRecord.Files {
				writePathRule(&b, "deny", "file-write*", sf.OriginalPath)
				writePathRule(&b, "allow", "file-read*", sf.OriginalPath)
			}
		}
	}

	// 3. Deny explicit secret paths (always enforced)
	b.WriteString("\n;; Explicit Denied Paths\n")
	for _, p := range s.plan.Filesystem.DeniedPaths {
		writePathRule(&b, "deny", "file-read* file-write*", p)
	}

	// 5. Allow explicit exceptions (takes precedence over previous deny)
	b.WriteString("\n;; Explicit Allowed Exceptions\n")
	for _, p := range s.plan.Filesystem.AllowedPaths {
		writePathRule(&b, "allow", "file-read*", p)
		base := filepath.Base(p)
		b.WriteString(fmt.Sprintf("(allow file-read* (regex #\"(^|/)%s$\"))\n", escapeRegex(base)))
	}

	// 5b. Allow access to ephemeral shadow workspace
	if s.shadowWorkspace != "" {
		b.WriteString("\n;; Shadow Workspace Access\n")
		writePathRule(&b, "allow", "file-read* file-write*", s.shadowWorkspace)
	}

	// 5c. System TLS & Certificate Trust Stores
	b.WriteString("\n;; System TLS & Certificate Trust Stores\n")
	writePathRule(&b, "allow", "file-read*", "/private/etc/ssl")
	writePathRule(&b, "allow", "file-read*", "/etc/ssl")
	writePathRule(&b, "allow", "file-read*", "/System/Library/Keychains")
	writePathRule(&b, "allow", "file-read*", "/Library/Keychains")
	writePathRule(&b, "allow", "file-read*", "/System/Library/Security")
	writePathRule(&b, "allow", "file-read*", "/System/Library/Frameworks/Security.framework")
	writePathRule(&b, "allow", "file-read*", "/usr/share/curl")

	// 6. IPC protection: file-level socket denial (network denial is emitted after the
	// network policy section so the operation-specific deny rules take precedence).
	b.WriteString("\n;; IPC Protection\n")
	for _, sock := range s.plan.IPC.BlockedSocketPaths {
		if sock != "" {
			writePathRule(&b, "deny", "file-read* file-write*", sock)
		}
	}

	// 7. Network policy.
	// Seatbelt resolves overlapping rules by operation specificity first and profile order
	// second, so the blanket Unix-socket allow must be followed by the per-socket denies.
	b.WriteString("\n;; Network Protection\n")
	if s.plan.Network.Mode == policy.NetworkModeDeny {
		b.WriteString("(deny network*)\n")
	} else if s.plan.Network.Mode == policy.NetworkModeRestricted {
		b.WriteString("(deny network-outbound)\n")
		b.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
		b.WriteString("(allow network-outbound (remote unix-socket))\n")
	}
	// Per-socket denies are emitted last so they override any broader Unix-socket allow.
	for _, sock := range s.plan.IPC.BlockedSocketPaths {
		if sock != "" {
			writeUnixSocketDenyRule(&b, sock)
		}
	}

	return b.String()
}

func writePathRule(b *strings.Builder, action, op, p string) {
	if p == "" {
		return
	}
	clean := filepath.Clean(p)
	b.WriteString(fmt.Sprintf("(%s %s (literal %q))\n", action, op, clean))
	b.WriteString(fmt.Sprintf("(%s %s (subpath %q))\n", action, op, clean))

	// Also add canonical symlink-resolved path for macOS /var -> /private/var, /tmp -> /private/tmp, etc.
	canon := canonicalizePath(clean)
	if canon != "" && canon != clean {
		b.WriteString(fmt.Sprintf("(%s %s (literal %q))\n", action, op, canon))
		b.WriteString(fmt.Sprintf("(%s %s (subpath %q))\n", action, op, canon))
	}
}

// writeUnixSocketDenyRule blocks connect(2) to a Unix domain socket. Seatbelt evaluates
// network socket paths after symlink resolution, so the canonical path is emitted too.
// The network-outbound operation is used so the rule takes precedence over a broader
// network-outbound allow for local Unix sockets.
func writeUnixSocketDenyRule(b *strings.Builder, p string) {
	if p == "" {
		return
	}
	clean := filepath.Clean(p)
	b.WriteString(fmt.Sprintf("(deny network-outbound (remote unix-socket (literal %q)))\n", clean))
	canon := canonicalizePath(clean)
	if canon != "" && canon != clean {
		b.WriteString(fmt.Sprintf("(deny network-outbound (remote unix-socket (literal %q)))\n", canon))
	}
}

func canonicalizePath(p string) string {
	clean := filepath.Clean(p)
	if canon, err := filepath.EvalSymlinks(clean); err == nil {
		return canon
	}
	// If path doesn't exist yet, resolve parent directory symlinks
	dir := filepath.Dir(clean)
	base := filepath.Base(clean)
	if canonDir, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Join(canonDir, base)
	}
	// Fallback check for standard macOS symlinks (/var -> /private/var, /tmp -> /private/tmp, /etc -> /private/etc)
	for _, prefix := range []string{"/tmp", "/var", "/etc"} {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return "/private" + clean
		}
	}
	return clean
}

func escapeRegex(s string) string {
	return regexp.QuoteMeta(s)
}
