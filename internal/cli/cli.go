package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/secretharbor/secretharbor/internal/agents"
	"github.com/secretharbor/secretharbor/internal/approval"
	"github.com/secretharbor/secretharbor/internal/audit"
	"github.com/secretharbor/secretharbor/internal/broker"
	"github.com/secretharbor/secretharbor/internal/cleaner"
	"github.com/secretharbor/secretharbor/internal/compiler"
	"github.com/secretharbor/secretharbor/internal/docker"
	"github.com/secretharbor/secretharbor/internal/network"
	"github.com/secretharbor/secretharbor/internal/policy"
	"github.com/secretharbor/secretharbor/internal/sandbox"
	"github.com/secretharbor/secretharbor/internal/secrets"
	"github.com/secretharbor/secretharbor/internal/session"
	"github.com/secretharbor/secretharbor/internal/vault"
)

var Version = "0.4.0-prod"

// ProcessExitError preserves the exact child process exit code (BUG-017).
type ProcessExitError struct {
	Code int
	Err  error
}

func (e *ProcessExitError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("process exited with status %d: %v", e.Code, e.Err)
	}
	return fmt.Sprintf("process exited with status %d", e.Code)
}

func (e *ProcessExitError) ExitCode() int {
	return e.Code
}

func (e *ProcessExitError) Unwrap() error {
	return e.Err
}

// DetermineProgName resolves whether the CLI was invoked as 'shb' or 'secretharbor'.
func DetermineProgName(defaultProg string) string {
	if defaultProg == "" {
		defaultProg = "shb"
	}
	if len(os.Args) > 0 && os.Args[0] != "" {
		base := filepath.Base(os.Args[0])
		if base == "shb" || base == "secretharbor" {
			return base
		}
	}
	return defaultProg
}

// Execute is the main entrypoint for both `shb` and `secretharbor` CLI binaries.
func Execute(defaultProg string) int {
	progName := DetermineProgName(defaultProg)

	if len(os.Args) >= 2 && os.Args[1] == sandbox.SandboxHelperArg {
		if err := sandbox.RunSandboxHelper(); err != nil {
			fmt.Fprintf(os.Stderr, "SecretHarbor sandbox helper failed: %v\n", err)
			return 1
		}
		return 0
	}

	if len(os.Args) < 2 {
		PrintUsage(progName)
		return 1
	}

	subcmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch subcmd {
	case "init":
		err = RunInit(progName, args)
	case "adopt":
		err = RunAdopt(progName, args)
	case "restart":
		err = RunRestart(progName, args)
	case "run":
		err = RunAgent(progName, args)
	case "status":
		err = RunStatus(progName)
	case "sessions":
		err = RunSessions(progName)
	case "stop":
		err = RunStop(progName, args)
	case "guard":
		err = RunGuard(progName, args)
	case "disable":
		err = RunGuard(progName, append([]string{"off"}, args...))
	case "enable":
		err = RunGuard(progName, append([]string{"on"}, args...))
	case "doctor":
		err = RunDoctor(progName)
	case "update":
		err = RunUpdate(progName, args)
	case "config":
		err = RunConfig(progName, args)
	case "trust":
		err = RunTrust(progName, args)
	case "policy":
		err = RunPolicy(progName, args)
	case "approve":
		err = RunApprove(progName, args)
	case "deny":
		err = RunDeny(progName, args)
	case "pending":
		err = RunPending(progName)
	case "secret":
		err = RunSecret(progName, args)
	case "restore":
		err = RunRestore(progName, args)
	case "env":
		err = RunEnv(progName, args)
	case "logs":
		err = RunLogs(progName, args)
	case "version", "--version", "-v":
		printVersion(progName, args)
		return 0
	case "help", "--help", "-h":
		cmd := ""
		if len(args) > 0 {
			cmd = args[0]
		}
		fmt.Print(RenderHelp(progName, cmd))
		return 0
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", subcmd)
		PrintUsage(progName)
		return 1
	}

	if err != nil {
		var pExitErr *ProcessExitError
		if errors.As(err, &pExitErr) {
			return pExitErr.Code
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "\033[31mError:\033[0m %v\n", err)
		return 1
	}
	return 0
}

func PrintUsage(progName string) {
	fmt.Print(RenderHelp(progName, ""))
}

func RunInit(progName string, args []string) error {
	autoConfirm := false
	force := false
	targetFile := "secretharbor.yaml"

	for _, arg := range args {
		if arg == "-y" || arg == "--yes" {
			autoConfirm = true
		} else if arg == "-f" || arg == "--force" {
			force = true
		} else if !strings.HasPrefix(arg, "-") {
			targetFile = arg
		}
	}

	cwd, _ := os.Getwd()
	displayPath := cwd
	if targetFile != "secretharbor.yaml" {
		displayPath = filepath.Dir(targetFile)
		if displayPath == "." || displayPath == "" {
			displayPath = cwd
		}
	}

	// 1. Create secretharbor.yaml if not present (or --force requested)
	createdConfig := false
	if _, err := os.Stat(targetFile); os.IsNotExist(err) || force {
		content := `# SecretHarbor Configuration File (v1)
# Documentation: https://secretharbor.dev

version: 1

# Protection presets: standard | strict | permissive
# - standard:   secret files faked, sensitive env sanitized, network allowed, escape denied
# - strict:     all secrets denied, strict network denial, no escapes
# - permissive: obvious secrets faked, network allowed
protection: standard

# Default secret virtualization mode: fake | deny | allow
secrets:
  mode: fake

# Exceptions to default secret handling
exceptions:
  allow:
    - .env.example
  deny:
    - .env.production
    - secrets/**

# Outbound network domain policy (allowed by default; domains can be explicitly denied)
network:
  mode: allow
  # Optional: explicitly deny specific domains
  # deny:
  #   - telemetry.example.com

# Local IPC endpoints and daemon protection
ipc:
  unix_sockets:
    mode: deny
  abstract_sockets:
    mode: deny
  docker:
    mode: approval

# Sandbox escape controls (human approval required)
sandbox:
  escape: deny
`
		if err := policy.AtomicWriteFile(targetFile, []byte(content), 0600); err != nil {
			return fmt.Errorf("failed to write %s: %w", targetFile, err)
		}
		createdConfig = true
	}

	// 1b. Clean orphaned sockets and scratch workspaces from dead sessions
	cleaner.CleanOrphans()

	// 2. Discover installed agents & desktop environments
	detected := agents.DetectInstalledAgents()

	// 3. Install transparent launcher shims
	shimsDir := agents.GetShimsDir()
	installedShims, _ := agents.InstallShims(shimsDir, detected)

	// 4. Configure shell profile PATH
	profilePath, profileUpdated, _ := agents.ConfigureShellProfile()

	// 5. Scan running processes for pre-existing agent instances
	runningProcs, _ := agents.ScanRunningProcesses()
	groups := agents.GroupAgentProcesses(runningProcs)
	var unprotected []*agents.RunningAppGroup
	totalProcs := 0
	for _, g := range groups {
		if !g.Protected {
			unprotected = append(unprotected, g)
			totalProcs += len(g.AllPIDs)
		}
	}

	// 6. Print initialization report
	fmt.Println()
	if createdConfig {
		fmt.Printf("\033[32m✓\033[0m SecretHarbor initialized for %s\n", displayPath)
	} else {
		fmt.Printf("\033[32m✓\033[0m SecretHarbor active for %s (using existing %s)\n", displayPath, filepath.Base(targetFile))
	}
	fmt.Println()

	fmt.Println("Detected agents:")
	if len(detected) == 0 {
		fmt.Println("  • No AI agents detected in PATH yet (shims will guard them once installed)")
	} else {
		for _, a := range detected {
			pkgInfo := ""
			if a.PackageType != "native" {
				pkgInfo = fmt.Sprintf(" (%s)", a.PackageType)
			}
			fmt.Printf("  \033[32m✓\033[0m %s%s\n", a.DisplayName, pkgInfo)
		}
	}
	fmt.Println()

	fmt.Println("Protection:")
	fmt.Println("  \033[32m✓\033[0m Secret files (.env, credentials, private keys)")
	fmt.Println("  \033[32m✓\033[0m Environment variables (sanitized & virtualized)")
	fmt.Println("  \033[32m✓\033[0m Network (outbound proxy domain allowlist)")
	fmt.Println("  \033[32m✓\033[0m Local IPC (Unix sockets and abstract namespaces denied)")
	fmt.Println("  \033[32m✓\033[0m Sandbox escape controls (containment boundary)")
	fmt.Println()

	fmt.Println("Integration:")
	fmt.Printf("  \033[32m✓\033[0m Transparent shims installed (%s, %d agents)\n", shimsDir, installedShims)
	if profileUpdated {
		fmt.Printf("  \033[32m✓\033[0m Shell PATH configured (%s)\n", profilePath)
	} else if profilePath != "" {
		fmt.Printf("  \033[32m✓\033[0m Shell PATH already configured in %s\n", profilePath)
	}
	fmt.Println()

	fmt.Println("Next steps:")
	fmt.Println("  • Just run your agents normally (e.g. `claude`, `codex`, `gemini`).")
	fmt.Println("  • Future launches will automatically run inside SecretHarbor.")
	fmt.Println("  • Persistence: integration remains active across reboots without re-running init.")

	// 7. Handle pre-existing running processes (No Retroactive Sandboxing Invariant)
	if len(unprotected) > 0 {
		fmt.Println()
		if totalProcs > len(unprotected) {
			fmt.Printf("Running processes (%d applications, %d total processes):\n", len(unprotected), totalProcs)
		} else {
			fmt.Println("Running processes:")
		}
		for _, g := range unprotected {
			if len(g.AllPIDs) > 1 {
				fmt.Printf("  • %s (PID %d, %d processes) — \033[33mUNPROTECTED\033[0m (started before SecretHarbor)\n", g.DisplayName, g.RootProcess.PID, len(g.AllPIDs))
			} else {
				fmt.Printf("  • %s (PID %d) — \033[33mUNPROTECTED\033[0m (started before SecretHarbor)\n", g.DisplayName, g.RootProcess.PID)
			}
			fmt.Println("    Constraint: active processes cannot be retroactively sandboxed.")
			fmt.Println("                The security boundary must exist before the process starts.")
		}
		fmt.Println()

		restartUnprotected := func() error {
			for _, targetGroup := range unprotected {
				if targetGroup == nil || targetGroup.RootProcess == nil || targetGroup.RootProcess.PID <= 1 {
					continue
				}
				fmt.Printf("Restarting %s under SecretHarbor protection...\n", targetGroup.DisplayName)
				type procIdent struct {
					start string
					name  string
				}
				idents := make(map[int]procIdent)
				for _, pid := range targetGroup.AllPIDs {
					s, n, _ := session.GetProcessIdentity(pid)
					idents[pid] = procIdent{start: s, name: n}
				}
				for _, pid := range targetGroup.AllPIDs {
					if pid > 1 && pid != os.Getpid() {
						_ = killProcess(pid, syscall.SIGTERM)
					}
				}
				time.Sleep(500 * time.Millisecond)
				for _, pid := range targetGroup.AllPIDs {
					if pid > 1 && pid != os.Getpid() && session.IsProcessAlive(pid) {
						expected := idents[pid]
						if expected.start != "" || expected.name != "" {
							currStart, currName, _ := session.GetProcessIdentity(pid)
							if (expected.start != "" && currStart != expected.start) || (expected.name != "" && currName != expected.name) {
								continue
							}
						}
						_ = killProcess(pid, syscall.SIGKILL)
					}
				}
				isGUI := targetGroup.IsGUIApp()
				exe := agents.ExtractExecutableFromCommand(targetGroup.RootProcess.Command)
				origArgs := targetGroup.RootProcess.Args
				var cmdArgs []string
				if isGUI && exe != "" {
					cmdArgs = []string{exe}
				} else {
					cmdArgs = []string{targetGroup.AgentID}
				}
				if len(origArgs) > 1 {
					cmdArgs = append(cmdArgs, origArgs[1:]...)
				}
				if autoConfirm || len(unprotected) > 1 {
					// Adopting multiple agents (or fully automatic mode) requires background
					// supervisors so every adopted agent keeps its own enforcement infrastructure.
					if err := RunAgent(progName, append([]string{"-d"}, cmdArgs...)); err != nil {
						return err
					}
					continue
				}
				return RunAgent(progName, cmdArgs)
			}
			return nil
		}

		if autoConfirm {
			return restartUnprotected()
		}

		if !isInputTerminal() {
			fmt.Println("Processes remain unprotected. Run 'shb adopt' at any time to adopt them.")
			return nil
		}

		fmt.Print("Restart now under SecretHarbor protection? [y/N] ")
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err == nil {
			input = strings.TrimSpace(strings.ToLower(input))
			if input == "y" || input == "yes" {
				return restartUnprotected()
			}
		}
		fmt.Println("Processes remain unprotected. Run 'shb adopt' at any time to adopt them.")
	}

	return nil
}

func RunAgent(progName string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing agent name or command. Usage: %s run [-d] <agent> or %s run -- <command...>", progName, progName)
	}

	for _, a := range args {
		if a == "-h" || a == "--help" {
			fmt.Print(RenderHelp(progName, "run"))
			return nil
		}
	}

	detach := false
	var cleanArgs []string
	afterDashDash := false
	for _, a := range args {
		if a == "--" {
			afterDashDash = true
			cleanArgs = append(cleanArgs, a)
		} else if !afterDashDash && (a == "-d" || a == "--detach") {
			detach = true
		} else {
			cleanArgs = append(cleanArgs, a)
		}
	}
	if len(cleanArgs) == 0 {
		return fmt.Errorf("missing agent name or command. Usage: %s run [-d] <agent> or %s run -- <command...>", progName, progName)
	}
	args = cleanArgs

	var alias string
	var subArgs []string

	if args[0] == "--" {
		alias = "--"
		subArgs = args[1:]
	} else {
		alias = args[0]
		subArgs = args[1:]
		if len(subArgs) > 0 && subArgs[0] == "--" {
			subArgs = subArgs[1:]
		}
	}

	target, err := agents.ResolveAgent(alias, subArgs)
	if err != nil {
		return err
	}

	cwd, _ := os.Getwd()

	if detach && os.Getenv("SECRETHARBOR_DETACHED_DAEMON") != "1" {
		// Fail fast on invalid policy before spawning the background supervisor.
		if _, _, err := policy.LoadPolicy(cwd); err != nil {
			return fmt.Errorf("enforcement unavailable: %w", err)
		}

		exe, err := os.Executable()
		if err != nil {
			exe = os.Args[0]
		}

		logDir := filepath.Join(filepath.Dir(session.GetSessionsDir()), "logs")
		if err := os.MkdirAll(logDir, 0700); err != nil {
			return fmt.Errorf("failed to create detached session log directory: %w", err)
		}
		logPath := filepath.Join(logDir, fmt.Sprintf("detached-%d.log", time.Now().UnixNano()))
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("failed to open detached session log: %w", err)
		}

		daemonCmd := exec.Command(exe, os.Args[1:]...)
		daemonCmd.Env = append(os.Environ(), "SECRETHARBOR_DETACHED_DAEMON=1")
		daemonCmd.Dir = cwd
		daemonCmd.SysProcAttr = getSysProcAttrSetsid()
		daemonCmd.Stdin = nil
		daemonCmd.Stdout = logFile
		daemonCmd.Stderr = logFile
		if err := daemonCmd.Start(); err != nil {
			_ = logFile.Close()
			return fmt.Errorf("failed to start detached daemon: %w", err)
		}
		_ = logFile.Close()

		fmt.Printf("\033[32m✓\033[0m Started %s in detached background daemon (PID %d)\n", target.Name, daemonCmd.Process.Pid)
		fmt.Printf("Session output log: %s\n", logPath)
		fmt.Printf("Run '%s sessions' to list the active session and '%s stop <id>' to terminate it.\n", progName, progName)
		return nil
	}

	// Clean any orphaned swaps from previously crashed sessions before launching
	_ = secrets.RestoreOrphanSwaps()

	cfg, configPath, err := policy.LoadPolicy(cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n\033[31mSecretHarbor enforcement unavailable.\033[0m\n")
		fmt.Fprintf(os.Stderr, "%s cannot be started safely.\n", target.Name)
		fmt.Fprintf(os.Stderr, "Reason: failed to load policy: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run: %s status / %s doctor\n\n", progName, progName)
		return fmt.Errorf("enforcement unavailable: %w", err)
	}

	// Check if guard is explicitly turned off for this project
	if !cfg.IsGuardEnabled() {
		fmt.Printf("\033[33m⚠️  WARNING: SecretHarbor guard is OFF for this project.\033[0m\n")
		fmt.Println("Running agent without sandbox confinement, secret virtualization, or network proxying.")
		fmt.Printf("Run '%s guard on' to re-enable security protections.\n\n", progName)

		cmd := exec.Command(target.Command, target.Args...)
		cmd.Dir = cwd
		cmd.Env = os.Environ()
		if agents.IsElectronOrChromiumApp(target.Command) {
			cmd.Stdin = nil
		} else {
			cmd.Stdin = os.Stdin
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start unconfined process: %w", err)
		}

		pid := cmd.Process.Pid
		pgid, _ := getProcessGroupID(pid)
		if pgid <= 0 {
			pgid = pid
		}

		sess, _ := session.Register(target.Name, target.Command, cwd, pid, pgid, "")
		if detach && os.Getenv("SECRETHARBOR_DETACHED_DAEMON") != "1" {
			fmt.Printf("\033[32m✓\033[0m Started %s (unconfined, PID %d)\n", target.Name, pid)
			if sess != nil {
				fmt.Printf("Active session %s registered. Run '%s stop %s' to terminate.\n", sess.ID, progName, target.Name)
			}
			return nil
		}

		defer func() {
			if sess != nil {
				_ = session.Unregister(sess.ID)
			}
		}()

		stopSig := forwardSignals(pid, pgid, func() {
			if sess != nil {
				_ = session.Unregister(sess.ID)
			}
		})
		defer stopSig()

		runErr := cmd.Wait()
		exitCode := exitCodeFromState(cmd.ProcessState)
		if runErr != nil && exitCode != 0 {
			return &ProcessExitError{Code: exitCode, Err: runErr}
		}
		return runErr
	}

	plan, err := compiler.Compile(cfg, configPath, cwd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n\033[31mSecretHarbor enforcement unavailable.\033[0m\n")
		fmt.Fprintf(os.Stderr, "%s cannot be started safely.\n", target.Name)
		fmt.Fprintf(os.Stderr, "Reason: failed to compile execution plan: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run: %s status / %s doctor\n\n", progName, progName)
		return fmt.Errorf("enforcement unavailable: %w", err)
	}

	// 1. Start local forward proxy if network is restricted
	var extraEnv []string
	extraEnv = append(extraEnv, "SECRETHARBOR_SANDBOX=1")
	var proxy *network.ForwardProxy
	if plan.Network.ProxyRequired {
		var pErr error
		proxy, pErr = network.StartForwardProxy(plan.Network.Mode, plan.Network.AllowedDomains, plan.Network.DeniedDomains)
		if pErr != nil {
			fmt.Fprintf(os.Stderr, "\n\033[31mSecretHarbor enforcement unavailable.\033[0m\n")
			fmt.Fprintf(os.Stderr, "%s cannot be started safely.\n", target.Name)
			fmt.Fprintf(os.Stderr, "Reason: failed to start network isolation proxy: %v\n", pErr)
			fmt.Fprintf(os.Stderr, "Run: %s status / %s doctor\n\n", progName, progName)
			return fmt.Errorf("enforcement unavailable: %w", pErr)
		}
		defer proxy.Close()
		proxy.SetBroker(broker.GlobalBroker)
		plan.Network.ProxyPort = proxy.Port()

		// Register capabilities for secrets configured with 'use' mode.
		// runtime.allow supplies fallback hosts for rules that omit explicit hosts.
		for _, rule := range plan.Policy.Rules {
			if rule.Use.Enabled {
				realSec, found, _ := vault.GlobalVault.Get(rule.Secret)
				if !found {
					realSec = os.Getenv(rule.Secret)
				}
				if realSec != "" {
					hosts := rule.Use.Hosts
					if len(hosts) == 0 {
						hosts = plan.Runtime.AllowedSecrets
					}
					fakeVal := secrets.GenerateFakeValue(rule.Secret)
					broker.GlobalBroker.Register(rule.Secret, fakeVal, realSec, hosts, 0)
				}
			}
		}

		proxyURL := proxy.ProxyURL()
		extraEnv = append(extraEnv,
			"HTTP_PROXY="+proxyURL,
			"HTTPS_PROXY="+proxyURL,
			"ALL_PROXY="+proxyURL,
			"http_proxy="+proxyURL,
			"https_proxy="+proxyURL,
			"all_proxy="+proxyURL,
			"NO_PROXY=localhost,127.0.0.1,::1",
			"no_proxy=localhost,127.0.0.1,::1",
		)

		if caCert := proxy.CACertPath(); caCert != "" {
			plan.Filesystem.AllowedPaths = append(plan.Filesystem.AllowedPaths, caCert)
			extraEnv = append(extraEnv,
				"SSL_CERT_FILE="+caCert,
				"NODE_EXTRA_CA_CERTS="+caCert,
				"REQUESTS_CA_BUNDLE="+caCert,
				"CURL_CA_BUNDLE="+caCert,
			)
		}
	}

	// 2. Start approval control socket
	if err := approval.GlobalManager.StartControlSocket(); err != nil {
		fmt.Fprintf(os.Stderr, "\033[33mWarning:\033[0m approval control socket unavailable: %v\n", err)
	}
	defer approval.GlobalManager.Stop()

	// 2b. Start Docker capability interceptor if Docker IPC is approval-gated
	var dockerInterceptor *docker.Interceptor
	if plan.IPC.DockerMode == policy.DockerIPCModeApproval {
		var dErr error
		dockerInterceptor, dErr = docker.StartInterceptor(target.Name, "")
		if dErr == nil {
			defer dockerInterceptor.Close()
			extraEnv = append(extraEnv, "DOCKER_HOST=unix://"+dockerInterceptor.SocketPath())
		}
	}

	// 3. Initialize and prepare OS sandbox
	sb, err := sandbox.New(plan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n\033[31mSecretHarbor enforcement unavailable.\033[0m\n")
		fmt.Fprintf(os.Stderr, "%s cannot be started safely.\n", target.Name)
		fmt.Fprintf(os.Stderr, "Reason: failed to initialize OS sandbox: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run: %s status / %s doctor\n\n", progName, progName)
		return fmt.Errorf("enforcement unavailable: %w", err)
	}
	if err := sb.Prepare(plan); err != nil {
		sb.Cleanup()
		fmt.Fprintf(os.Stderr, "\n\033[31mSecretHarbor enforcement unavailable.\033[0m\n")
		fmt.Fprintf(os.Stderr, "%s cannot be started safely.\n", target.Name)
		fmt.Fprintf(os.Stderr, "Reason: failed to prepare sandbox environment: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run: %s status / %s doctor\n\n", progName, progName)
		return fmt.Errorf("enforcement unavailable: %w", err)
	}
	// 4. Log launch event (sanitizing/redacting agent arguments)
	redactedArgs := audit.Redact(strings.Join(target.Args, " "))
	audit.GlobalLogger.Log(target.Name, "launch", target.Command, "sandbox_active", redactedArgs)

	// 5. Execute sandboxed command
	cmd, err := sb.Launch(target.Command, target.Args, extraEnv)
	if err != nil {
		sb.Cleanup()
		return fmt.Errorf("failed to launch sandboxed process: %w", err)
	}

	// The detached supervisor process owns stdio (redirected to its session log);
	// only null it out for a foreground parent that is about to exit.
	if detach && os.Getenv("SECRETHARBOR_DETACHED_DAEMON") != "1" {
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
	}

	if err := cmd.Start(); err != nil {
		sb.Cleanup()
		return fmt.Errorf("failed to start sandboxed process: %w", err)
	}

	pid := cmd.Process.Pid
	secrets.UpdateSwapPID(cwd, pid)
	if dockerInterceptor != nil {
		dockerInterceptor.SetPID(pid)
	}
	pgid, _ := getProcessGroupID(pid)
	if pgid <= 0 {
		pgid = pid
	}

	shadowDir := ""
	if cmd.Dir != "" && cmd.Dir != cwd {
		shadowDir = cmd.Dir
	}

	sess, _ := session.Register(target.Name, target.Command, cwd, pid, pgid, shadowDir)
	if detach && os.Getenv("SECRETHARBOR_DETACHED_DAEMON") != "1" {
		fmt.Printf("\033[32m✓\033[0m Started %s inside SecretHarbor sandbox (PID %d)\n", target.Name, pid)
		if sess != nil {
			fmt.Printf("Active session %s registered. Run '%s stop %s' to terminate.\n", sess.ID, progName, target.Name)
		}
		return nil
	}

	defer sb.Cleanup()

	defer func() {
		if sess != nil {
			_ = session.Unregister(sess.ID)
		}
	}()

	stopSig := forwardSignals(pid, pgid, func() {
		if sess != nil {
			_ = session.Unregister(sess.ID)
		}
		_ = secrets.RestoreSwapForPID(pid)
		_ = secrets.RestoreSwapForDirectory(cwd)
		if dockerInterceptor != nil {
			_ = dockerInterceptor.Close()
		}
		approval.GlobalManager.Stop()
		if plan.Network.ProxyRequired && proxy != nil {
			_ = proxy.Close()
		}
		sb.Cleanup()
	})
	defer stopSig()

	runErr := cmd.Wait()
	exitCode := exitCodeFromState(cmd.ProcessState)

	audit.GlobalLogger.Log(target.Name, "exit", target.Command, fmt.Sprintf("exit_%d", exitCode), "")

	if runErr != nil && exitCode != 0 {
		return &ProcessExitError{Code: exitCode, Err: runErr}
	}
	return runErr
}

func RunStatus(progName string) error {
	cwd, _ := os.Getwd()
	cfg, configPath, err := policy.LoadPolicy(cwd)
	if err != nil {
		return err
	}

	plan, err := compiler.Compile(cfg, configPath, cwd)
	if err != nil {
		return err
	}

	cleaner.CleanOrphans()

	activeSwaps, _ := secrets.LoadActiveSwaps()
	var secretFiles []string
	cleanCwd := filepath.Clean(cwd)
	for proj, rec := range activeSwaps {
		if filepath.Clean(proj) == cleanCwd && rec != nil {
			for _, f := range rec.Files {
				secretFiles = append(secretFiles, f.OriginalPath)
			}
		}
	}
	sessions, _ := session.List()
	runningProcs, _ := agents.ScanRunningProcesses()

	var unprotected []*agents.RunningAgentProcess
	for _, p := range runningProcs {
		if !p.Protected {
			unprotected = append(unprotected, p)
		}
	}

	guardStatus := "\033[32mON (protected)\033[0m"
	if !cfg.IsGuardEnabled() {
		guardStatus = "\033[33mOFF (unrestricted access)\033[0m"
	}

	kernelEnforcement, filesystemIsolation, networkIsolation, ipcIsolation, fdProtection := enforcementPosture(cfg)

	shimsDir := agents.GetShimsDir()
	shimsInstalled := "active"
	if _, err := os.Stat(shimsDir); os.IsNotExist(err) {
		shimsInstalled = "not installed (run 'shb init')"
	}

	pathStatus := "active in PATH"
	if !agents.IsShimsDirInPATH() {
		pathStatus = "configured in profile (restart shell to activate)"
	}

	policyLocation := plan.ConfigPath
	if policyLocation == "" {
		policyLocation = "none (using standard preset; run 'shb init' to create)"
	}

	fmt.Printf("SecretHarbor Status (via %s)\n", progName)
	fmt.Println(stringsRepeat("─", 55))
	fmt.Printf("Guard Status:                %s\n", guardStatus)
	fmt.Printf("Protection Level:            %s\n", cfg.Protection)
	fmt.Printf("Host Platform:               %s (%s)\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Policy Location:             %s\n", policyLocation)
	fmt.Printf("Launcher Shims:              %s (%s)\n", shimsInstalled, shimsDir)
	fmt.Printf("Shell PATH:                  %s\n", pathStatus)
	fmt.Printf("Kernel Enforcement:          %s\n", kernelEnforcement)
	fmt.Printf("Filesystem Isolation:        %s\n", filesystemIsolation)
	fmt.Printf("Network Isolation:           %s\n", networkIsolation)
	fmt.Printf("IPC Isolation:               %s\n", ipcIsolation)
	dockerCap := string(cfg.IPC.Docker.Mode)
	if cfg.IPC.Docker.Mode == policy.DockerIPCModeApproval {
		dockerCap = "approval-gated (capability intercepted)"
	}
	if !cfg.IsGuardEnabled() {
		dockerCap = "disabled (guard off)"
	}
	fmt.Printf("Docker Capability:           %s\n", dockerCap)
	if cfg.IsGuardEnabled() {
		fmt.Printf("Environment Sanitization:    active (%s mode)\n", cfg.Environment.Mode)
	} else {
		fmt.Printf("Environment Sanitization:    disabled (guard off)\n")
	}
	fmt.Printf("Inherited FD Protection:     %s\n", fdProtection)
	fmt.Printf("Unsandboxed Escape:          %s\n", cfg.Sandbox.Escape)
	fmt.Printf("Protected Secret Files:      %d detected\n", len(secretFiles))
	for _, f := range secretFiles {
		rel, err := filepath.Rel(cwd, f)
		if err != nil {
			rel = f
		}
		fmt.Printf("  • %s\n", rel)
	}

	fmt.Printf("Active Agent Sessions:       %d running\n", len(sessions))
	for _, s := range sessions {
		if s == nil {
			continue
		}
		fmt.Printf("  • [%s] %-10s (Project: %s, PID %d, Status: \033[32mPROTECTED\033[0m)\n", s.ID, s.Agent, s.Project, s.PID)
		for _, p := range runningProcs {
			if p != nil && p.PID == s.PID && p.Hierarchy != nil {
				fmt.Println("    Process Hierarchy:")
				fmt.Print(p.Hierarchy.RenderTree("      "))
				break
			}
		}
	}

	fmt.Printf("Unprotected Agent Processes: %d running\n", len(unprotected))
	for _, p := range unprotected {
		if p == nil {
			continue
		}
		fmt.Printf("  • %-10s PID %-7d Status: \033[33mUNPROTECTED\033[0m (run '%s adopt' or '%s restart %s' to guard)\n", p.DisplayName, p.PID, progName, progName, p.AgentID)
		if p.Hierarchy != nil {
			fmt.Println("    Process Hierarchy:")
			fmt.Print(p.Hierarchy.RenderTree("      "))
		}
	}

	fmt.Println(stringsRepeat("─", 55))
	if !cfg.IsGuardEnabled() {
		fmt.Println("Overall Posture:             \033[33mGUARD DISABLED\033[0m")
	} else if len(unprotected) > 0 {
		fmt.Printf("Overall Posture:             \033[33mATTENTION (%d unprotected agent(s) detected; run '%s adopt')\033[0m\n", len(unprotected), progName)
	} else {
		fmt.Println("Overall Posture:             \033[32mSTRONG (all systems protected)\033[0m")
	}
	return nil
}

func RunSessions(progName string) error {
	sessions, err := session.List()
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	if len(sessions) == 0 {
		fmt.Println("No active SecretHarbor sessions.")
		return nil
	}

	fmt.Println("SecretHarbor Sessions")
	fmt.Println()
	PrintSessionTable(sessions)
	return nil
}

func PrintSessionTable(sessions []*session.Session) {
	fmt.Printf("%-8s %-10s %-12s %s\n", "ID", "Agent", "Project", "Status")
	for _, s := range sessions {
		fmt.Printf("%-8s %-10s %-12s %s\n", s.ID, s.Agent, s.Project, s.Status)
	}
}

func RunStop(progName string, args []string) error {
	var targetSess *session.Session
	var err error

	if len(args) > 0 {
		targetSess, err = session.Get(args[0])
		if err != nil {
			return err
		}
	} else {
		cwd, _ := os.Getwd()
		targetSess, err = session.GetForProject(cwd)
		if err != nil {
			sessions, listErr := session.List()
			if listErr != nil {
				return listErr
			}
			if len(sessions) == 0 {
				fmt.Println("No active SecretHarbor sessions found.")
				return nil
			}
			if len(sessions) == 1 {
				targetSess = sessions[0]
			} else {
				fmt.Println("Multiple active sessions found. Specify session ID to stop:")
				fmt.Println()
				PrintSessionTable(sessions)
				fmt.Printf("\nUsage: %s stop <id>\n", progName)
				return nil
			}
		}
	}

	fmt.Printf("Stopping agent session %s (%s, PID %d)...\n", targetSess.ID, targetSess.Agent, targetSess.PID)
	if err := session.StopSession(targetSess); err != nil {
		return fmt.Errorf("failed to cleanly stop session: %w", err)
	}
	_ = secrets.RestoreSwap(targetSess.ProjectDir)

	fmt.Printf("\033[32m✓ Stopped agent session %s (%s, PID %d)\033[0m\n", targetSess.ID, targetSess.Agent, targetSess.PID)
	fmt.Println("Temporary sandbox state cleaned up.")
	fmt.Printf("\033[90mNote: '%s stop' terminates an agent session. SecretHarbor security policy remains active.\033[0m\n", progName)
	return nil
}

// isSandboxedAgent reports whether the current process is running inside a SecretHarbor sandbox.
func isSandboxedAgent() bool {
	return os.Getenv("SECRETHARBOR_SANDBOX") == "1" || os.Getenv("SHB_SANDBOX") == "1"
}

// enforcementPosture reports what is actually enforced on this host rather than echoing policy intent.
func enforcementPosture(cfg *policy.Config) (kernel, filesystem, network, ipc, fd string) {
	if !cfg.IsGuardEnabled() {
		return "disabled (guard off)", "disabled (guard off)", "disabled (guard off)", "disabled (guard off)", "disabled (guard off)"
	}

	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("sandbox-exec"); err != nil {
			kernel = "unavailable (sandbox-exec missing)"
			filesystem = "not enforced"
			ipc = "not enforced"
		} else {
			kernel = "active (Apple Seatbelt)"
			filesystem = fmt.Sprintf("kernel-enforced (%s mode)", cfg.Secrets.Mode)
			ipc = fmt.Sprintf("kernel-enforced (Unix sockets: %s)", cfg.IPC.UnixSockets.Mode)
		}
	case "linux":
		kernel = "limited (namespaces only; Landlock not applied)"
		filesystem = "not enforced (mount/Landlock policy not applied)"
		ipc = "not enforced"
	case "windows":
		kernel = "unavailable (developer preview)"
		filesystem = "not enforced"
		ipc = "not enforced"
	default:
		kernel = "unavailable"
		filesystem = "not enforced"
		ipc = "not enforced"
	}

	switch cfg.Network.Mode {
	case policy.NetworkModeDeny:
		if runtime.GOOS == "darwin" {
			network = "deny (kernel-enforced by Seatbelt)"
		} else {
			network = "deny (proxy-based; bypassable by non-proxy-aware clients)"
		}
	case policy.NetworkModeRestricted:
		if runtime.GOOS == "darwin" {
			network = fmt.Sprintf("restricted (%d allowed domains; kernel-enforced loopback proxy)", len(cfg.Network.Allow))
		} else {
			network = fmt.Sprintf("restricted (%d allowed domains; proxy-based, bypassable)", len(cfg.Network.Allow))
		}
	default:
		if len(cfg.Network.Deny) > 0 {
			network = "allow with denylist (proxy-based; cooperative clients)"
		} else {
			network = "allow (unrestricted)"
		}
	}

	if runtime.GOOS == "windows" {
		fd = "not enforced"
	} else {
		fd = "best-effort (close-on-exec)"
	}
	return
}

func RunGuard(progName string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s guard [on|off]", progName)
	}

	// STRICT SECURITY BOUNDARY: sandboxed agents must never alter their own enforcement state.
	if isSandboxedAgent() {
		return fmt.Errorf("Permission denied: SecretHarbor guard state is human-controlled. Sandboxed agents cannot modify the security boundary.")
	}

	action := strings.ToLower(args[0])
	cwd, _ := os.Getwd()
	cfg, configPath, err := policy.LoadPolicy(cwd)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	if configPath == "" {
		configPath = filepath.Join(cwd, policy.DefaultConfigFileName)
	}

	switch action {
	case "on", "enable":
		cfg.Guard = "on"
		if err := policy.SavePolicyToFile(configPath, cfg); err != nil {
			return fmt.Errorf("failed to update policy file: %w", err)
		}
		fmt.Printf("\033[32m✓ SecretHarbor guard is now ON for this project.\033[0m\n")
		fmt.Printf("Sandbox confinement, secret virtualization, and network policy are active.\n")
		return nil

	case "off", "disable":
		autoConfirm := false
		for _, arg := range args[1:] {
			if arg == "-y" || arg == "--yes" || arg == "--force" {
				autoConfirm = true
				break
			}
		}

		if !autoConfirm {
			fmt.Printf("\033[33mSecretHarbor protection will be disabled for this project.\033[0m\n\n")
			fmt.Println("The next agent session may have unrestricted access to:")
			fmt.Println("  .env")
			fmt.Println("  credentials")
			fmt.Println("  SSH keys")
			fmt.Println("  local services")
			fmt.Println("  network")
			fmt.Println()
			fmt.Print("Continue? [y/N] ")

			reader := bufio.NewReader(os.Stdin)
			input, _ := reader.ReadString('\n')
			input = strings.TrimSpace(strings.ToLower(input))
			if input != "y" && input != "yes" {
				fmt.Println("Operation cancelled. SecretHarbor guard remains ON.")
				return nil
			}
		}

		cfg.Guard = "off"
		if err := policy.SavePolicyToFile(configPath, cfg); err != nil {
			return fmt.Errorf("failed to update policy file: %w", err)
		}
		fmt.Printf("\033[33m⚠️  SecretHarbor guard has been turned OFF for this project.\033[0m\n")
		fmt.Printf("Next agent sessions will run with unrestricted host access.\n")
		fmt.Printf("Run '%s guard on' to re-enable protections.\n", progName)
		return nil

	default:
		return fmt.Errorf("unknown guard action %q. Usage: %s guard [on|off]", action, progName)
	}
}

func RunApprove(progName string, args []string) error {
	targetID := ""
	if len(args) > 0 {
		targetID = args[0]
	}
	resp, err := approval.SendControlCommand("APPROVE " + targetID)
	if err != nil {
		return err
	}
	fmt.Println(resp)
	return nil
}

func RunDeny(progName string, args []string) error {
	targetID := ""
	if len(args) > 0 {
		targetID = args[0]
	}
	resp, err := approval.SendControlCommand("DENY " + targetID)
	if err != nil {
		return err
	}
	fmt.Println(resp)
	return nil
}

func RunPending(progName string) error {
	resp, err := approval.SendControlCommand("LIST")
	if err != nil {
		return err
	}

	var list []*approval.Request
	if err := json.Unmarshal([]byte(resp), &list); err != nil {
		return fmt.Errorf("invalid response: %s", resp)
	}

	if len(list) == 0 {
		fmt.Println("No pending capability escalation requests.")
		return nil
	}

	fmt.Printf("Active Escalation Requests (%d pending):\n", len(list))
	for _, req := range list {
		fmt.Printf("  [%s] Agent: %s (PID %d) | Capability: %s\n      Details: %s\n",
			req.ID, req.AgentName, req.PID, req.Capability, req.Details)
	}
	return nil
}

func RunLogs(progName string, args []string) error {
	limit := 20
	if len(args) > 0 {
		parsed, parseErr := strconv.Atoi(strings.TrimSpace(args[0]))
		if parseErr != nil || parsed <= 0 {
			return fmt.Errorf("invalid log limit %q (expected a positive integer). Usage: %s logs [limit]", args[0], progName)
		}
		limit = parsed
	}
	events, err := audit.ReadLogs(limit)
	if err != nil {
		return fmt.Errorf("failed to read audit logs: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No audit log events recorded yet.")
		return nil
	}

	fmt.Printf("SecretHarbor Security Events (Last %d):\n", len(events))
	fmt.Println(stringsRepeat("─", 78))
	for _, ev := range events {
		fmt.Printf("[%s] Agent: %-10s Op: %-8s Res: %-18s Result: %s\n",
			ev.Timestamp.Format("15:04:05"), ev.Agent, ev.Operation, ev.Resource, ev.Result)
	}
	return nil
}

type VersionInfo struct {
	Version        string `json:"version"`
	ProgName       string `json:"program"`
	Platform       string `json:"platform"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Kernel         string `json:"kernel"`
	SandboxDriver  string `json:"sandbox_driver"`
	PolicyVersion  string `json:"policy_version"`
	VaultAlgorithm string `json:"vault_algorithm"`
	ControlBroker  string `json:"control_broker"`
}

func printVersion(progName string, args []string) {
	isJSON := false
	for _, arg := range args {
		if arg == "--json" || arg == "-j" {
			isJSON = true
			break
		}
	}

	kernel := getKernelVersion()
	driver := detectSandboxDriver()
	policyVer := "v1 (none loaded)"
	cwd, err := os.Getwd()
	if err == nil {
		if cfg, _, err := policy.LoadPolicy(cwd); err == nil && cfg != nil {
			guardStr := "on"
			if !cfg.IsGuardEnabled() {
				guardStr = "off"
			}
			policyVer = fmt.Sprintf("v%d (%s, guard: %s)", cfg.Version, cfg.Protection, guardStr)
		}
	}

	info := VersionInfo{
		Version:        Version,
		ProgName:       progName,
		Platform:       fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Kernel:         kernel,
		SandboxDriver:  driver,
		PolicyVersion:  policyVer,
		VaultAlgorithm: "AES-256-GCM encrypted",
		ControlBroker:  "Unix Domain Socket (IPC)",
	}

	if isJSON {
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Printf("SecretHarbor v%s (%s/%s) [%s]\n", Version, runtime.GOOS, runtime.GOARCH, progName)
	fmt.Printf("  Kernel:           %s\n", kernel)
	fmt.Printf("  Sandbox Driver:   %s\n", driver)
	fmt.Printf("  Active Policy:    %s\n", policyVer)
	fmt.Printf("  Vault Storage:    %s\n", info.VaultAlgorithm)
	fmt.Printf("  Control Broker:   %s\n", info.ControlBroker)
}

func getKernelVersion() string {
	out, err := exec.Command("uname", "-srm").Output()
	if err == nil && len(out) > 0 {
		return strings.TrimSpace(string(out))
	}
	return fmt.Sprintf("%s (%s)", runtime.GOOS, runtime.GOARCH)
}

func detectSandboxDriver() string {
	switch runtime.GOOS {
	case "darwin":
		return "seatbelt (sandbox-exec, libsandbox)"
	case "linux":
		return "landlock / namespaces / bpf"
	case "windows":
		return "restricted-token / job-object"
	default:
		return "posix-chroot-fallback"
	}
}

func isInputTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// KillProcessTree terminates rootPID and all of its descendant child processes.
func KillProcessTree(rootPID int) {
	session.KillProcessTree(rootPID)
}

// exitCodeFromState returns the child's exit status, mapping signal termination to 128+signal.
func exitCodeFromState(state *os.ProcessState) int {
	if state == nil {
		return 0
	}
	if code := state.ExitCode(); code >= 0 {
		return code
	}
	if ws, ok := state.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return 1
}

// forwardSignals routes interrupts and termination signals to the child process tree.
// On any interrupt (Ctrl+C) or termination signal, it immediately terminates the entire
// process tree (including all helper/worker processes), runs cleanup routines, and exits with status 130.
func forwardSignals(pid, pgid int, cleanup func()) func() {
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})

	go func() {
		select {
		case <-sigChan:
			KillProcessTree(pid)
			if pgid > 0 && pgid != getProcessGroup() {
				_ = killProcessGroup(pgid, syscall.SIGKILL)
			}
			if cleanup != nil {
				cleanup()
			}
			os.Exit(130)
		case <-done:
			return
		}
	}()

	return func() {
		close(done)
		signal.Stop(sigChan)
	}
}

// RunRestore restores swapped secret files to their original real values.
func RunRestore(progName string, args []string) error {
	all := false
	orphans := false
	targetDir := ""

	for _, a := range args {
		if a == "--all" || a == "-a" {
			all = true
		} else if a == "--orphans" || a == "-o" {
			orphans = true
		} else if !strings.HasPrefix(a, "-") {
			targetDir = a
		}
	}

	if all {
		count := secrets.RestoreAllSwaps()
		fmt.Printf("\033[32m✓ Restored real secrets across %d project(s)\033[0m\n", count)
		return nil
	}

	if orphans {
		count := secrets.RestoreOrphanSwaps()
		fmt.Printf("\033[32m✓ Restored %d orphaned project swap(s)\033[0m\n", count)
		return nil
	}

	if targetDir == "" {
		targetDir, _ = os.Getwd()
	}

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		absDir = targetDir
	}

	if err := secrets.RestoreSwap(absDir); err != nil {
		return fmt.Errorf("failed to restore secrets: %w", err)
	}

	fmt.Printf("\033[32m✓ Restored real secrets for %s\033[0m\n", absDir)
	return nil
}

// RunEnv manages environment file editing during active sessions and host workflows.
func RunEnv(progName string, args []string) error {
	action := "edit"
	if len(args) > 0 {
		action = strings.ToLower(args[0])
	}

	switch action {
	case "edit":
		cwd, _ := os.Getwd()
		absCwd, _ := filepath.Abs(cwd)
		swaps, _ := secrets.LoadActiveSwaps()
		rec, isSwapped := swaps[absCwd]

		var targetFile string
		if isSwapped && rec != nil && len(rec.Files) > 0 {
			// Edit the real file in secure backup
			targetFile = rec.Files[0].BackupPath
		} else {
			targetFile = filepath.Join(cwd, ".env")
		}

		if _, err := os.Stat(targetFile); os.IsNotExist(err) {
			return fmt.Errorf("no .env file found to edit at %s", targetFile)
		}

		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "nano"
			if _, err := exec.LookPath("nano"); err != nil {
				editor = "vi"
			}
		}

		cmd := exec.Command(editor, targetFile)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			return fmt.Errorf("editor exited with error: %w", err)
		}

		if isSwapped && rec != nil && len(rec.Files) > 0 {
			// Refresh in-tree synthetic fake file
			realBytes, err := os.ReadFile(rec.Files[0].BackupPath)
			if err == nil {
				virtualized, err := secrets.VirtualizeEnvContent(bytes.NewReader(realBytes))
				if err == nil {
					projHash := secrets.ProjectHash(absCwd)
					var b strings.Builder
					b.WriteString(secrets.SyntheticWatermark + "\n")
					b.WriteString(fmt.Sprintf("# Project Hash: %s | Real secrets secured in ~/.secretharbor/vault\n", projHash))
					b.WriteString("# Safe synthetic values generated for process isolation.\n\n")
					b.WriteString(virtualized)
					_ = os.WriteFile(rec.Files[0].OriginalPath, []byte(b.String()), rec.Files[0].FileMode)
				}
			}
			fmt.Printf("\033[32m✓ Real secrets updated and synthetic environment refreshed for active session\033[0m\n")
		} else {
			fmt.Printf("\033[32m✓ Saved %s\033[0m\n", targetFile)
		}
		return nil

	default:
		return fmt.Errorf("unknown env command: %s. Usage: %s env [edit]", action, progName)
	}
}
