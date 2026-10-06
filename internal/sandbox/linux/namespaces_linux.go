//go:build linux

package linux

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/secretharbor/secretharbor/internal/environment"
	"github.com/secretharbor/secretharbor/internal/fd"
	"github.com/secretharbor/secretharbor/internal/policy"
	"golang.org/x/sys/unix"
)

type helperSpec struct {
	Command     string            `json:"command"`
	Args        []string          `json:"args"`
	ProjectDir  string            `json:"project_dir"`
	AllowedDirs []string          `json:"allowed_dirs"`
	DeniedPaths []string          `json:"denied_paths"`
	FakeFiles   map[string]string `json:"fake_files,omitempty"`
}

func (s *LinuxSandbox) launchPlatform(command string, args []string, extraEnv []string) (*exec.Cmd, error) {
	rawEnv := append(os.Environ(), extraEnv...)
	envCfg := &s.plan.Environment.Effective
	if envCfg.Mode == "" && s.plan.Policy != nil {
		envCfg = &s.plan.Policy.Environment
	}
	res := environment.Sanitize(rawEnv, envCfg)
	finalEnv := append([]string(nil), res.FinalEnv...)

	if s.plan.IPC.DockerMode == policy.DockerIPCModeApproval {
		for _, extra := range extraEnv {
			if strings.HasPrefix(extra, "DOCKER_HOST=unix://") {
				finalEnv = append(finalEnv, extra)
				break
			}
		}
	}

	if err := fd.CloseUnexpectedFDs(nil); err != nil {
		return nil, fmt.Errorf("failed to sanitize file descriptors: %w", err)
	}

	allowedDirs := append([]string{s.plan.ProjectDir}, s.plan.Filesystem.AllowedPaths...)
	fakeFiles := make(map[string]string)
	for real, fake := range s.plan.Filesystem.FakeFiles {
		fakeFiles[real] = fake
	}

	spec := helperSpec{
		Command:     command,
		Args:        append([]string(nil), args...),
		ProjectDir:  s.plan.ProjectDir,
		AllowedDirs: allowedDirs,
		DeniedPaths: append([]string(nil), s.plan.Filesystem.DeniedPaths...),
		FakeFiles:   fakeFiles,
	}
	specData, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to encode sandbox spec: %w", err)
	}

	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}

	cmd := exec.Command(exe, SandboxHelperArg)
	cmd.Dir = s.plan.ProjectDir
	cmd.Env = append(finalEnv, SandboxHelperEnv+"="+base64.StdEncoding.EncodeToString(specData))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Unprivileged user namespace + mount namespace + IPC isolation. A network namespace
	// is added for full deny mode; restricted mode keeps the host network namespace because
	// its loopback proxy lives there.
	cloneFlags := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWIPC)
	if s.plan.Network.Mode == policy.NetworkModeDeny {
		cloneFlags |= syscall.CLONE_NEWNET
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: cloneFlags,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			},
		},
		Pdeathsig: syscall.SIGKILL,
	}

	return cmd, nil
}

// RunSandboxHelper applies mount virtualization, process hardening, and Landlock rules,
// then execs the target command. It must fail closed: any failure aborts before exec.
func RunSandboxHelper() error {
	raw := os.Getenv(SandboxHelperEnv)
	if raw == "" {
		return fmt.Errorf("missing sandbox spec")
	}
	specData, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return fmt.Errorf("invalid sandbox spec encoding: %w", err)
	}

	var spec helperSpec
	if err := json.Unmarshal(specData, &spec); err != nil {
		return fmt.Errorf("invalid sandbox spec: %w", err)
	}
	if spec.Command == "" {
		return fmt.Errorf("sandbox spec has no command")
	}

	targetEnv := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, SandboxHelperEnv+"=") {
			continue
		}
		targetEnv = append(targetEnv, entry)
	}

	if err := SetupMountNamespace(spec.AllowedDirs); err != nil {
		return fmt.Errorf("failed to configure mount namespace: %w", err)
	}

	// Bind synthetic fakes over real secret files inside the namespace (kernel virtualization).
	for realPath, fakePath := range spec.FakeFiles {
		if _, err := os.Stat(realPath); err != nil {
			continue
		}
		if err := bindMountReadOnly(fakePath, realPath); err != nil {
			return fmt.Errorf("failed to virtualize secret %s: %w", realPath, err)
		}
	}

	// Mask denied paths that live inside an allowed directory (Landlock cannot express deny rules).
	maskDir, err := os.MkdirTemp("", "shb-mask-*")
	if err != nil {
		return fmt.Errorf("failed to create mask directory: %w", err)
	}
	defer os.RemoveAll(maskDir)
	maskFile := filepath.Join(maskDir, "empty")
	if err := os.WriteFile(maskFile, nil, 0600); err != nil {
		return fmt.Errorf("failed to create mask file: %w", err)
	}
	emptyDir := filepath.Join(maskDir, "emptydir")
	if err := os.Mkdir(emptyDir, 0700); err != nil {
		return fmt.Errorf("failed to create mask dir: %w", err)
	}

	for _, denied := range spec.DeniedPaths {
		if denied == "" {
			continue
		}
		if !isUnderAny(denied, spec.AllowedDirs) {
			continue
		}
		fi, err := os.Lstat(denied)
		if err != nil {
			continue
		}
		source := maskFile
		if fi.IsDir() {
			source = emptyDir
		}
		if err := bindMountReadOnly(source, denied); err != nil {
			return fmt.Errorf("failed to mask denied path %s: %w", denied, err)
		}
	}

	// Apply process hardening (PR_SET_DUMPABLE=0)
	ApplyProcessHardening()

	// Apply Landlock LSM allowlist boundary last; restrictions survive exec.
	if err := ApplyLandlockRuleset(spec.AllowedDirs, spec.DeniedPaths); err != nil {
		return fmt.Errorf("failed to apply Landlock ruleset: %w", err)
	}

	execArgs := append([]string{spec.Command}, spec.Args...)
	return syscall.Exec(spec.Command, execArgs, targetEnv)
}

// SetupMountNamespace configures mount isolation with MS_REC|MS_PRIVATE,
// read-only system mounts, and bind mounts for allowed directories.
func SetupMountNamespace(allowedDirs []string) error {
	// Recursive private mount propagation ensures sandbox mounts don't propagate to host
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("failed to configure mount propagation MS_REC|MS_PRIVATE: %w", err)
	}

	// Read-only system mounts
	systemMounts := []string{"/usr", "/lib", "/lib64", "/bin", "/etc"}
	for _, m := range systemMounts {
		if _, err := os.Stat(m); err == nil {
			_ = unix.Mount(m, m, "", unix.MS_BIND|unix.MS_REC, "")
			_ = unix.Mount("", m, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_REC, "")
		}
	}

	// Bind mounts for allowed directories
	for _, dir := range allowedDirs {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(dir); err == nil {
			_ = unix.Mount(dir, dir, "", unix.MS_BIND|unix.MS_REC, "")
		}
	}

	return nil
}

func bindMountReadOnly(source, target string) error {
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return err
	}
	return nil
}

func isUnderAny(path string, dirs []string) bool {
	cleanPath := filepath.Clean(path)
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		cleanDir := filepath.Clean(dir)
		if cleanPath == cleanDir || strings.HasPrefix(cleanPath, cleanDir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// ApplyProcessHardening applies prctl(PR_SET_DUMPABLE, 0) inside Linux process.
func ApplyProcessHardening() {
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
