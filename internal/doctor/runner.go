package doctor

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/secretharbor/secretharbor/internal/compiler"
	"github.com/secretharbor/secretharbor/internal/policy"
	"github.com/secretharbor/secretharbor/internal/sandbox"
)

// TestStatus represents the result of an adversarial security test.
type TestStatus string

const (
	StatusPass      TestStatus = "PASS"
	StatusFail      TestStatus = "FAIL"
	StatusLimited   TestStatus = "LIMITED"
	StatusNotTested TestStatus = "NOT TESTED"
)

// Result records the outcome and diagnostic details of an adversarial test.
type Result struct {
	Category string     `json:"category"`
	Name     string     `json:"name"`
	Status   TestStatus `json:"status"`
	Details  string     `json:"details"`
}

// DoctorSuite manages and executes adversarial verification scenarios.
type DoctorSuite struct {
	projectDir string
	cfg        *policy.Config
	plan       *compiler.CompiledPlan
}

const (
	CanaryRealSecret = "sk_live_SUPER_SECRET_CANARY_VALUE_12345"
	CanaryDBPassword = "super_secret_database_password_canary"
)

// NewSuite creates a new verification suite.
func NewSuite(projectDir string, cfg *policy.Config) (*DoctorSuite, error) {
	plan, err := compiler.Compile(cfg, filepath.Join(projectDir, "secretharbor.yaml"), projectDir)
	if err != nil {
		return nil, err
	}
	return &DoctorSuite{
		projectDir: projectDir,
		cfg:        cfg,
		plan:       plan,
	}, nil
}

// RunAll executes all adversarial verification tests.
func (d *DoctorSuite) RunAll() []Result {
	// Create an isolated sandbox environment fixture with real canary secret
	fixtureDir, err := os.MkdirTemp("", "secretharbor-doctor-fixture-*")
	if err != nil {
		return []Result{{
			Category: "Setup",
			Name:     "Fixture Creation",
			Status:   StatusFail,
			Details:  fmt.Sprintf("Failed to create fixture dir: %v", err),
		}}
	}
	defer os.RemoveAll(fixtureDir)

	// Write canary secret file
	canaryEnv := fmt.Sprintf("STRIPE_SECRET_KEY=%s\nDATABASE_URL=postgresql://user:%s@db:5432/prod\n",
		CanaryRealSecret, CanaryDBPassword)
	envPath := filepath.Join(fixtureDir, ".env")
	if err := os.WriteFile(envPath, []byte(canaryEnv), 0600); err != nil {
		return []Result{{
			Category: "Setup",
			Name:     "Canary Setup",
			Status:   StatusFail,
			Details:  fmt.Sprintf("Failed to write canary secret: %v", err),
		}}
	}

	// Create control-plane fixture policy file in a dedicated directory
	fixtureControlDir := filepath.Join(fixtureDir, ".control_plane")
	_ = os.MkdirAll(fixtureControlDir, 0700)
	fixturePolicyFile := filepath.Join(fixtureControlDir, "policy.yaml")
	_ = os.WriteFile(fixturePolicyFile, []byte("version: 1\nprotection: standard\n"), 0600)

	// Recompile plan for fixtureDir with fixturePolicyFile protected
	plan, err := compiler.Compile(d.cfg, fixturePolicyFile, fixtureDir)
	if err != nil {
		return []Result{{
			Category: "Setup",
			Name:     "Plan Compilation",
			Status:   StatusFail,
			Details:  err.Error(),
		}}
	}
	plan.Filesystem.SelfProtectedPaths = append(plan.Filesystem.SelfProtectedPaths, fixturePolicyFile, fixtureControlDir)

	sb, err := sandbox.New(plan)
	if err != nil {
		return []Result{{
			Category: "Sandbox",
			Name:     "Sandbox Creation",
			Status:   StatusFail,
			Details:  err.Error(),
		}}
	}
	if err := sb.Prepare(plan); err != nil {
		return []Result{{
			Category: "Sandbox",
			Name:     "Sandbox Prepare",
			Status:   StatusFail,
			Details:  err.Error(),
		}}
	}
	defer sb.Cleanup()

	var results []Result

	// 1. Filesystem: Direct secret read
	results = append(results, d.testDirectRead(sb, fixtureDir))

	// 2. Filesystem: Python interpreter read
	results = append(results, d.testPythonRead(sb, fixtureDir))

	// 3. Filesystem: Node interpreter read
	results = append(results, d.testNodeRead(sb, fixtureDir))

	// 4. Filesystem: Symlink bypass
	results = append(results, d.testSymlinkBypass(sb, fixtureDir))

	// 5. Filesystem: Path traversal
	results = append(results, d.testPathTraversal(sb, fixtureDir))

	// 6. Filesystem: Copy bypass
	results = append(results, d.testCopyBypass(sb, fixtureDir))

	// 7. Filesystem: Rename bypass
	results = append(results, d.testRenameBypass(sb, fixtureDir))

	// 8. Environment: Real secret environment exposure
	results = append(results, d.testSecretEnvExposure(sb, fixtureDir))

	// 9. Environment: SSH_AUTH_SOCK exposure
	results = append(results, d.testSSHAuthSockExposure(sb, fixtureDir))

	// 10. IPC: Docker socket access
	results = append(results, d.testDockerSocketAccess(sb, fixtureDir))

	// 11. IPC: DOCKER_HOST privileged IPC leakage
	results = append(results, d.testDockerHostExposure(sb, fixtureDir))

	// 12. Container: /run/secrets inspection
	results = append(results, d.testContainerSecretInspection(sb, fixtureDir))

	// 13. File Descriptors: Unexpected FD inheritance (without test setting CLOEXEC)
	results = append(results, d.testFDInheritance(sb, fixtureDir))

	// 14. Control Plane: Policy file modification (against fixture)
	results = append(results, d.testPolicyTampering(sb, fixturePolicyFile, fixtureDir))

	// 15. Process: ptrace attempt
	results = append(results, d.testPtraceAttempt(sb, fixtureDir))

	// 16. Process: Core dump behavior
	results = append(results, d.testCoreDumpBehavior(sb, fixtureDir))

	// 17. Network: Network egress isolation
	results = append(results, d.testNetworkIsolation(sb, fixtureDir))

	// 18. Escape: Root filesystem / sandbox escape
	results = append(results, d.testSandboxEscape(sb, fixtureDir))

	return results
}

func (d *DoctorSuite) runCommand(sb sandbox.Sandbox, dir, command string, args []string, extraEnv []string) (string, int, error) {
	// The sandbox launch owns the working directory (shadow workspace in fake mode).
	cmd, err := sb.Launch(command, args, extraEnv)
	if err != nil {
		return "", -1, err
	}

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err = cmd.Run()
	output := outBuf.String() + "\n" + errBuf.String()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	return output, exitCode, err
}

func (d *DoctorSuite) containsAnyCanary(output string) bool {
	return strings.Contains(output, CanaryRealSecret) || strings.Contains(output, CanaryDBPassword)
}

func (d *DoctorSuite) testDirectRead(sb sandbox.Sandbox, dir string) Result {
	output, _, _ := d.runCommand(sb, dir, "cat", []string{".env"}, nil)
	if d.containsAnyCanary(output) {
		return Result{
			Category: "Filesystem",
			Name:     "Direct Secret Read (cat .env)",
			Status:   StatusFail,
			Details:  "Real secret value leaked to agent stdout",
		}
	}
	return Result{
		Category: "Filesystem",
		Name:     "Direct Secret Read (cat .env)",
		Status:   StatusPass,
		Details:  "Real secret protected (denied or virtualized)",
	}
}

func (d *DoctorSuite) testPythonRead(sb sandbox.Sandbox, dir string) Result {
	if _, err := exec.LookPath("python3"); err != nil {
		return Result{
			Category: "Interpreters",
			Name:     "Python Read",
			Status:   StatusNotTested,
			Details:  "python3 executable not available on host",
		}
	}

	code := "try:\n print(open('.env').read())\nexcept Exception as e:\n print('BLOCKED:', e)\n"
	output, _, _ := d.runCommand(sb, dir, "python3", []string{"-c", code}, nil)
	if d.containsAnyCanary(output) {
		return Result{
			Category: "Interpreters",
			Name:     "Python Interpreter Read",
			Status:   StatusFail,
			Details:  "Python script accessed real secret file",
		}
	}
	return Result{
		Category: "Interpreters",
		Name:     "Python Interpreter Read",
		Status:   StatusPass,
		Details:  "Python execution prevented from reading real secret",
	}
}

func (d *DoctorSuite) testNodeRead(sb sandbox.Sandbox, dir string) Result {
	if _, err := exec.LookPath("node"); err != nil {
		return Result{
			Category: "Interpreters",
			Name:     "Node Read",
			Status:   StatusNotTested,
			Details:  "node executable not available on host",
		}
	}

	code := "try { console.log(require('fs').readFileSync('.env','utf8')); } catch(e) { console.log('BLOCKED:', e.message); }"
	output, _, _ := d.runCommand(sb, dir, "node", []string{"-e", code}, nil)
	if d.containsAnyCanary(output) {
		return Result{
			Category: "Interpreters",
			Name:     "Node Interpreter Read",
			Status:   StatusFail,
			Details:  "Node process read real secret file",
		}
	}
	return Result{
		Category: "Interpreters",
		Name:     "Node Interpreter Read",
		Status:   StatusPass,
		Details:  "Node execution prevented from reading real secret",
	}
}

func (d *DoctorSuite) testSymlinkBypass(sb sandbox.Sandbox, dir string) Result {
	script := "ln -sf .env symlink.env 2>/dev/null; cat symlink.env 2>&1"
	output, _, _ := d.runCommand(sb, dir, "/bin/sh", []string{"-c", script}, nil)
	if d.containsAnyCanary(output) {
		return Result{
			Category: "Filesystem",
			Name:     "Symlink Bypass",
			Status:   StatusFail,
			Details:  "Symlink read exposed real secret",
		}
	}
	return Result{
		Category: "Filesystem",
		Name:     "Symlink Bypass",
		Status:   StatusPass,
		Details:  "Symlink attempt blocked or returned synthetic content",
	}
}

func (d *DoctorSuite) testPathTraversal(sb sandbox.Sandbox, dir string) Result {
	script := "mkdir -p sub && cat sub/../.env 2>&1"
	output, _, _ := d.runCommand(sb, dir, "/bin/sh", []string{"-c", script}, nil)
	if d.containsAnyCanary(output) {
		return Result{
			Category: "Filesystem",
			Name:     "Path Traversal (../.env)",
			Status:   StatusFail,
			Details:  "Path traversal exposed real secret",
		}
	}
	return Result{
		Category: "Filesystem",
		Name:     "Path Traversal (../.env)",
		Status:   StatusPass,
		Details:  "Traversal attack blocked or returned synthetic content",
	}
}

func (d *DoctorSuite) testCopyBypass(sb sandbox.Sandbox, dir string) Result {
	script := "cp .env /tmp/leak.env 2>/dev/null && cat /tmp/leak.env 2>&1"
	output, _, _ := d.runCommand(sb, dir, "/bin/sh", []string{"-c", script}, nil)
	_ = os.Remove("/tmp/leak.env")
	if d.containsAnyCanary(output) {
		return Result{
			Category: "Filesystem",
			Name:     "Copy Bypass (cp .env /tmp)",
			Status:   StatusFail,
			Details:  "Copy of .env contained real secret",
		}
	}
	return Result{
		Category: "Filesystem",
		Name:     "Copy Bypass (cp .env /tmp)",
		Status:   StatusPass,
		Details:  "File copy prevented from exposing real credentials",
	}
}

func (d *DoctorSuite) testRenameBypass(sb sandbox.Sandbox, dir string) Result {
	// Renaming the synthetic file inside the sandbox is harmless; the real secret file
	// must remain untouched and no canary content may leak through the renamed file.
	script := "mv .env renamed.env 2>/dev/null; cat renamed.env 2>&1"
	output, _, _ := d.runCommand(sb, dir, "/bin/sh", []string{"-c", script}, nil)
	if d.containsAnyCanary(output) {
		return Result{
			Category: "Filesystem",
			Name:     "Rename Bypass (mv .env)",
			Status:   StatusFail,
			Details:  "Renamed file exposed real secret content",
		}
	}

	realEnv, err := os.ReadFile(filepath.Join(dir, ".env"))
	if err != nil || !strings.Contains(string(realEnv), CanaryRealSecret) {
		return Result{
			Category: "Filesystem",
			Name:     "Rename Bypass (mv .env)",
			Status:   StatusFail,
			Details:  "Real secret file was modified or removed by the sandboxed agent",
		}
	}

	return Result{
		Category: "Filesystem",
		Name:     "Rename Bypass (mv .env)",
		Status:   StatusPass,
		Details:  "Real secret file untouched; synthetic file rename is isolated",
	}
}

func (d *DoctorSuite) testSecretEnvExposure(sb sandbox.Sandbox, dir string) Result {
	extra := []string{"STRIPE_SECRET_KEY=" + CanaryRealSecret}
	output, _, _ := d.runCommand(sb, dir, "printenv", []string{"STRIPE_SECRET_KEY"}, extra)
	if strings.TrimSpace(output) == CanaryRealSecret {
		return Result{
			Category: "Environment",
			Name:     "Real Secret Env Var Exposure",
			Status:   StatusFail,
			Details:  "Host secret environment variable leaked unmodified to agent",
		}
	}
	return Result{
		Category: "Environment",
		Name:     "Real Secret Env Var Exposure",
		Status:   StatusPass,
		Details:  "Secret variable stripped or sanitized with synthetic value",
	}
}

func (d *DoctorSuite) testSSHAuthSockExposure(sb sandbox.Sandbox, dir string) Result {
	extra := []string{"SSH_AUTH_SOCK=/tmp/canary_ssh_auth_sock.sock"}
	output, _, _ := d.runCommand(sb, dir, "printenv", []string{"SSH_AUTH_SOCK"}, extra)
	if strings.Contains(output, "canary_ssh_auth_sock") {
		return Result{
			Category: "Environment",
			Name:     "SSH_AUTH_SOCK Privileged IPC Exposure",
			Status:   StatusFail,
			Details:  "Privileged SSH_AUTH_SOCK leaked to child environment",
		}
	}
	return Result{
		Category: "Environment",
		Name:     "SSH_AUTH_SOCK Privileged IPC Exposure",
		Status:   StatusPass,
		Details:  "SSH_AUTH_SOCK stripped from agent environment",
	}
}

func (d *DoctorSuite) testDockerSocketAccess(sb sandbox.Sandbox, dir string) Result {
	socketPath := ""
	for _, candidate := range []string{"/var/run/docker.sock", "/run/podman/podman.sock"} {
		if fi, err := os.Stat(candidate); err == nil && fi.Mode()&os.ModeSocket != 0 {
			socketPath = candidate
			break
		}
	}
	if socketPath == "" {
		return Result{
			Category: "IPC",
			Name:     "Privileged Docker Socket Access",
			Status:   StatusNotTested,
			Details:  "No Docker/Podman daemon socket present on this host",
		}
	}
	if _, err := exec.LookPath("python3"); err != nil {
		return Result{
			Category: "IPC",
			Name:     "Privileged Docker Socket Access",
			Status:   StatusNotTested,
			Details:  "python3 not available to probe Docker socket reachability",
		}
	}

	code := fmt.Sprintf("import socket\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect(%q)\n print('CONNECTED')\nexcept Exception as e:\n print('BLOCKED', e)\n", socketPath)
	output, _, _ := d.runCommand(sb, dir, "python3", []string{"-c", code}, nil)
	if strings.Contains(output, "CONNECTED") {
		return Result{
			Category: "IPC",
			Name:     "Privileged Docker Socket Access",
			Status:   StatusFail,
			Details:  fmt.Sprintf("Agent connected to privileged Docker socket %s", socketPath),
		}
	}
	if strings.Contains(output, "BLOCKED") {
		return Result{
			Category: "IPC",
			Name:     "Privileged Docker Socket Access",
			Status:   StatusPass,
			Details:  "Docker daemon socket connection denied by security boundary",
		}
	}
	return Result{
		Category: "IPC",
		Name:     "Privileged Docker Socket Access",
		Status:   StatusLimited,
		Details:  "Docker socket probe inconclusive",
	}
}

func (d *DoctorSuite) testDockerHostExposure(sb sandbox.Sandbox, dir string) Result {
	extra := []string{
		"DOCKER_HOST=unix:///tmp/canary_docker.sock",
		"CONTAINER_HOST=unix:///tmp/canary_podman.sock",
		"DOCKER_CONTEXT=canary_ctx",
	}
	output, _, _ := d.runCommand(sb, dir, "printenv", nil, extra)
	if strings.Contains(output, "canary_docker") || strings.Contains(output, "canary_podman") || strings.Contains(output, "canary_ctx") {
		return Result{
			Category: "IPC",
			Name:     "DOCKER_HOST Privileged IPC Leakage",
			Status:   StatusFail,
			Details:  "Unsanitized Docker/container host variables leaked to child process",
		}
	}
	return Result{
		Category: "IPC",
		Name:     "DOCKER_HOST Privileged IPC Leakage",
		Status:   StatusPass,
		Details:  "Privileged container environment variables purged from agent environment",
	}
}

func (d *DoctorSuite) testContainerSecretInspection(sb sandbox.Sandbox, dir string) Result {
	output, exitCode, _ := d.runCommand(sb, dir, "cat", []string{"/run/secrets/canary"}, nil)
	if d.containsAnyCanary(output) {
		return Result{
			Category: "Container",
			Name:     "Container Secret Directory Inspection (/run/secrets)",
			Status:   StatusFail,
			Details:  "Container secret directory exposed real secret data",
		}
	}
	if exitCode != 0 || strings.Contains(output, "denied") || strings.Contains(output, "No such file") {
		return Result{
			Category: "Container",
			Name:     "Container Secret Directory Inspection (/run/secrets)",
			Status:   StatusPass,
			Details:  "Container secrets directory protected or inaccessible",
		}
	}
	return Result{
		Category: "Container",
		Name:     "Container Secret Directory Inspection (/run/secrets)",
		Status:   StatusPass,
		Details:  "Container secret directory inspection neutralized",
	}
}

func (d *DoctorSuite) testFDInheritance(sb sandbox.Sandbox, dir string) Result {
	// Open a canary sensitive file on a descriptor WITHOUT setting CLOEXEC
	canaryPath := filepath.Join(dir, "canary_fd.txt")
	_ = os.WriteFile(canaryPath, []byte(CanaryRealSecret), 0600)

	fdNum, err := syscall.Open(canaryPath, syscall.O_RDONLY, 0)
	if err != nil {
		return Result{
			Category: "File Descriptors",
			Name:     "Sensitive Descriptor Leak",
			Status:   StatusNotTested,
			Details:  "Could not open canary descriptor",
		}
	}
	defer syscall.Close(fdNum)

	// Note: DO NOT set CLOEXEC here! The sandbox launch itself must sanitize descriptors.

	// Agent attempts to read from this descriptor
	script := fmt.Sprintf("cat <&%d 2>&1", fdNum)
	output, exitCode, err := d.runCommand(sb, dir, "/bin/sh", []string{"-c", script}, nil)

	if strings.Contains(output, CanaryRealSecret) {
		return Result{
			Category: "File Descriptors",
			Name:     "Sensitive Descriptor Leak",
			Status:   StatusFail,
			Details:  fmt.Sprintf("Agent process successfully read sensitive content from inherited fd %d", fdNum),
		}
	}

	if exitCode != 0 || err != nil || strings.Contains(output, "Bad file descriptor") || strings.Contains(output, "bad file number") {
		return Result{
			Category: "File Descriptors",
			Name:     "Sensitive Descriptor Leak (Close-on-Exec)",
			Status:   StatusPass,
			Details:  fmt.Sprintf("Parent descriptor %d inaccessible to agent (EBADF)", fdNum),
		}
	}

	return Result{
		Category: "File Descriptors",
		Name:     "Sensitive Descriptor Leak (Close-on-Exec)",
		Status:   StatusPass,
		Details:  "No sensitive data leaked through inherited descriptors",
	}
}

func (d *DoctorSuite) testPolicyTampering(sb sandbox.Sandbox, fixturePolicyFile, dir string) Result {
	script := `echo 'attack: true' >> "$SHB_PROBE_POLICY" 2>&1`
	output, exitCode, _ := d.runCommand(sb, dir, "/bin/sh", []string{"-c", script}, []string{"SHB_PROBE_POLICY=" + fixturePolicyFile})

	data, err := os.ReadFile(fixturePolicyFile)
	if err == nil && strings.Contains(string(data), "attack: true") {
		return Result{
			Category: "Control Plane",
			Name:     "Policy File Modification",
			Status:   StatusFail,
			Details:  "Agent was able to modify SecretHarbor policy fixture file",
		}
	}

	if exitCode == 0 && !strings.Contains(output, "denied") && !strings.Contains(output, "permitted") {
		return Result{
			Category: "Control Plane",
			Name:     "Policy File Modification",
			Status:   StatusFail,
			Details:  "Agent modified control plane without error",
		}
	}
	return Result{
		Category: "Control Plane",
		Name:     "Policy File Modification",
		Status:   StatusPass,
		Details:  "Control-plane policy modifications denied to agent",
	}
}

func (d *DoctorSuite) testPtraceAttempt(sb sandbox.Sandbox, dir string) Result {
	if _, err := exec.LookPath("python3"); err != nil {
		return Result{
			Category: "Process",
			Name:     "Process Memory Tracing (ptrace)",
			Status:   StatusNotTested,
			Details:  "python3 not available to perform ptrace probe",
		}
	}

	script := "python3 -c 'import ctypes; libc=ctypes.CDLL(None); res=libc.ptrace(0, 0, 0, 0); print(res)' 2>&1"
	output, exitCode, err := d.runCommand(sb, dir, "/bin/sh", []string{"-c", script}, nil)
	if err != nil || exitCode != 0 || strings.Contains(output, "denied") || strings.Contains(output, "-1") || strings.Contains(output, "not permitted") {
		return Result{
			Category: "Process",
			Name:     "Process Memory Tracing (ptrace)",
			Status:   StatusPass,
			Details:  "ptrace / debugger attachment prevented by security boundary",
		}
	}
	if strings.TrimSpace(output) == "0" {
		return Result{
			Category: "Process",
			Name:     "Process Memory Tracing (ptrace)",
			Status:   StatusLimited,
			Details:  "ptrace permitted inside local process context",
		}
	}
	return Result{
		Category: "Process",
		Name:     "Process Memory Tracing (ptrace)",
		Status:   StatusPass,
		Details:  "Process memory tracing prevented",
	}
}

func (d *DoctorSuite) testCoreDumpBehavior(sb sandbox.Sandbox, dir string) Result {
	output, _, _ := d.runCommand(sb, dir, "/bin/sh", []string{"-c", "ulimit -c"}, nil)
	outTrimmed := strings.TrimSpace(output)
	return Result{
		Category: "Process",
		Name:     "Core Dump Restrictions",
		Status:   StatusLimited,
		Details:  fmt.Sprintf("host core-dump limit is %q; SecretHarbor does not set a per-process core-dump limit", outTrimmed),
	}
}

func (d *DoctorSuite) testNetworkIsolation(sb sandbox.Sandbox, dir string) Result {
	if d.cfg == nil || d.cfg.Network.Mode == policy.NetworkModeAllow {
		return Result{
			Category: "Network",
			Name:     "Network Egress Isolation",
			Status:   StatusLimited,
			Details:  "network.mode=allow: outbound egress is intentionally unrestricted",
		}
	}
	if _, err := exec.LookPath("python3"); err != nil {
		return Result{
			Category: "Network",
			Name:     "Network Egress Isolation",
			Status:   StatusNotTested,
			Details:  "python3 not available to perform raw egress probe",
		}
	}

	// Loopback must stay reachable so the local forward proxy and app RPC continue to work.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Result{
			Category: "Network",
			Name:     "Network Egress Isolation",
			Status:   StatusNotTested,
			Details:  fmt.Sprintf("could not start controlled probe listener: %v", err),
		}
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port

	loopbackProbe := fmt.Sprintf("import socket\ns=socket.socket()\ns.settimeout(1)\ntry:\n s.connect(('127.0.0.1', %d))\n print('CONNECTED')\nexcept Exception as e:\n print('BLOCKED', e)\n", port)
	loopbackOut, _, _ := d.runCommand(sb, dir, "python3", []string{"-c", loopbackProbe}, nil)
	if !strings.Contains(loopbackOut, "CONNECTED") {
		return Result{
			Category: "Network",
			Name:     "Network Egress Isolation",
			Status:   StatusFail,
			Details:  "Loopback is unreachable; the local proxy and application RPC cannot function",
		}
	}

	// Raw egress to a non-loopback destination must be blocked by the kernel boundary.
	remoteProbe := "import socket\ns=socket.socket()\ns.settimeout(2)\ntry:\n s.connect(('1.1.1.1', 53))\n print('REMOTE_CONNECTED')\nexcept Exception as e:\n print('REMOTE_BLOCKED', e)\n"
	remoteOut, _, _ := d.runCommand(sb, dir, "python3", []string{"-c", remoteProbe}, nil)
	if strings.Contains(remoteOut, "REMOTE_CONNECTED") {
		return Result{
			Category: "Network",
			Name:     "Network Egress Isolation",
			Status:   StatusFail,
			Details:  "Raw TCP egress succeeded despite restricted/deny policy; network enforcement is bypassable",
		}
	}
	if strings.Contains(remoteOut, "REMOTE_BLOCKED") && strings.Contains(remoteOut, "Operation not permitted") {
		return Result{
			Category: "Network",
			Name:     "Network Egress Isolation",
			Status:   StatusPass,
			Details:  "Raw TCP egress denied by the kernel boundary; loopback proxy remains available",
		}
	}
	return Result{
		Category: "Network",
		Name:     "Network Egress Isolation",
		Status:   StatusLimited,
		Details:  "Remote egress probe was inconclusive (network unavailable or non-kernel denial)",
	}
}

func (d *DoctorSuite) testSandboxEscape(sb sandbox.Sandbox, dir string) Result {
	output, exitCode, _ := d.runCommand(sb, dir, "/bin/sh", []string{"-c", "touch /root_escape_test 2>&1; rm -f /root_escape_test 2>/dev/null"}, nil)
	if strings.Contains(output, "denied") || strings.Contains(output, "Read-only file system") || strings.Contains(output, "Operation not permitted") {
		return Result{
			Category: "Escape Attempts",
			Name:     "Root Filesystem Escape",
			Status:   StatusPass,
			Details:  "Root filesystem write denied",
		}
	}
	if exitCode == 0 {
		return Result{
			Category: "Escape Attempts",
			Name:     "Root Filesystem Escape",
			Status:   StatusFail,
			Details:  "Agent wrote outside project root to host filesystem",
		}
	}
	return Result{
		Category: "Escape Attempts",
		Name:     "Root Filesystem Escape",
		Status:   StatusLimited,
		Details:  "Root filesystem write failed for an unidentified reason",
	}
}
