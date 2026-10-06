package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/secretharbor/secretharbor/internal/policy"
	"github.com/secretharbor/secretharbor/internal/secrets"
)

// RunPolicy handles `shb policy <check|explain> [resource]`.
func RunPolicy(progName string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s policy <check|explain> [resource]", progName)
	}

	action := strings.ToLower(args[0])
	switch action {
	case "check":
		return runConfigCheck(progName, args[1:])
	case "explain":
		if len(args) < 2 {
			return fmt.Errorf("usage: %s policy explain <resource> (e.g. .env, DATABASE_URL, --network api.stripe.com)", progName)
		}
		return runPolicyExplain(progName, args[1:])
	default:
		return fmt.Errorf("unknown policy subcommand: %s. Usage: %s policy <check|explain> [resource]", action, progName)
	}
}

func runPolicyExplain(progName string, args []string) error {
	target := args[0]
	isNetwork := false
	if target == "--network" || target == "-n" {
		if len(args) < 2 {
			return fmt.Errorf("missing network host for --network flag")
		}
		isNetwork = true
		target = args[1]
	}

	cwd, _ := os.Getwd()
	cfg, configPath, err := policy.LoadPolicy(cwd)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	relConfig := configPath
	if r, err := filepath.Rel(cwd, configPath); err == nil {
		relConfig = r
	}

	// 1. Check if it's explicitly a network host flag
	if isNetwork {
		return explainNetworkPolicy(target, cfg, relConfig)
	}

	// 2. Check if target exists on disk as a file or directory
	if fileExists(target) || fileExists(filepath.Join(cwd, target)) {
		return explainFilePolicy(target, cwd, cfg, relConfig)
	}

	// 3. Check if target has common file extensions or path prefixes
	if hasFileExtension(target) || strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") || strings.HasPrefix(target, "~") || strings.HasPrefix(target, "/") {
		return explainFilePolicy(target, cwd, cfg, relConfig)
	}

	// 4. Check if it looks like a domain
	if looksLikeDomain(target) {
		return explainNetworkPolicy(target, cfg, relConfig)
	}

	// 5. Check if it's an environment variable (all caps, or commonly known)
	if isEnvVar(target) {
		return explainEnvPolicy(target, cfg, relConfig)
	}

	// 6. Otherwise treat as a filesystem path
	return explainFilePolicy(target, cwd, cfg, relConfig)
}

func explainFilePolicy(path, cwd string, cfg *policy.Config, relConfig string) error {
	home, _ := os.UserHomeDir()
	expandedPath := path
	if home != "" {
		if path == "~" {
			expandedPath = home
		} else if strings.HasPrefix(path, "~/") {
			expandedPath = filepath.Join(home, path[2:])
		}
	}

	absPath := expandedPath
	if !filepath.IsAbs(absPath) {
		absPath = filepath.Join(cwd, expandedPath)
	}
	absPath = filepath.Clean(absPath)
	cleanPath := filepath.Clean(path)
	fileName := filepath.Base(absPath)

	relToCwd, _ := filepath.Rel(cwd, absPath)
	relToHome := ""
	if home != "" {
		if r, err := filepath.Rel(home, absPath); err == nil && !strings.HasPrefix(r, "..") {
			relToHome = r
		}
	}

	isDir := false
	exists := true
	if fi, err := os.Stat(absPath); err == nil {
		isDir = fi.IsDir()
	} else if os.IsNotExist(err) {
		exists = false
	}

	matchedRule := ""
	source := fmt.Sprintf("protection: %s (%s)", cfg.Protection, relConfig)
	agentRead := "ALLOW"
	agentWrite := "ALLOW"
	agentDelete := "ALLOW"

	matchTarget := func(pattern string) bool {
		return matchPathPattern(pattern, absPath, relToCwd, relToHome, fileName, home, isDir)
	}

	// Check explicit allow exceptions first
	for _, a := range cfg.Exceptions.Allow {
		if matchTarget(a) {
			matchedRule = fmt.Sprintf("exceptions.allow rule %q", a)
			source = fmt.Sprintf("project %s", relConfig)
			agentRead = "ALLOW"
			agentWrite = "ALLOW"
			agentDelete = "ALLOW"
			break
		}
	}

	// Check explicit deny exceptions
	if matchedRule == "" {
		for _, d := range cfg.Exceptions.Deny {
			if matchTarget(d) {
				matchedRule = fmt.Sprintf("exceptions.deny rule %q", d)
				source = fmt.Sprintf("project %s", relConfig)
				agentRead = "DENY"
				agentWrite = "DENY"
				agentDelete = "DENY"
				break
			}
		}
	}

	// Check built-in secret patterns
	if matchedRule == "" {
		for _, p := range policy.BuiltInSecretPatterns {
			if matchTarget(p) {
				matchedRule = fmt.Sprintf("built-in secret pattern (%s)", p)
				source = fmt.Sprintf("protection: %s", cfg.Protection)
				if cfg.Secrets.Mode == policy.SecretModeFake {
					agentRead = "FAKE"
					agentWrite = "DENY (shadow synced)"
					agentDelete = "DENY"
				} else if cfg.Secrets.Mode == policy.SecretModeDeny {
					agentRead = "DENY"
					agentWrite = "DENY"
					agentDelete = "DENY"
				} else {
					agentRead = "ALLOW"
					agentWrite = "ALLOW"
					agentDelete = "ALLOW"
				}
				break
			}
		}
	}

	// Common sensitive home directories
	if matchedRule == "" && (strings.Contains(absPath, ".ssh") || strings.Contains(absPath, ".aws") || strings.Contains(absPath, ".gnupg")) {
		matchedRule = "built-in sensitive home directory protection"
		agentRead = "DENY"
		agentWrite = "DENY"
		agentDelete = "DENY"
	}

	if matchedRule == "" {
		matchedRule = "default workspace filesystem rule"
		agentRead = "ALLOW"
		agentWrite = "ALLOW"
		agentDelete = "ALLOW"
		source = "workspace policy (non-secret file)"
	}

	// If Guard is OFF
	if !cfg.IsGuardEnabled() {
		agentRead = "ALLOW (Guard OFF)"
		agentWrite = "ALLOW (Guard OFF)"
		agentDelete = "ALLOW (Guard OFF)"
		source = "guard: off (unrestricted host access)"
	}

	resourceSuffix := ""
	if isDir {
		resourceSuffix = " (Directory)"
	} else if !exists {
		resourceSuffix = " (nonexistent path; policy will apply if created)"
	}

	fmt.Printf("Resource: %s%s\n\n", cleanPath, resourceSuffix)
	fmt.Printf("Matched rule:\n  %s\n\n", matchedRule)
	fmt.Println("Effective access:")
	fmt.Printf("  Agent read:   %s\n", agentRead)
	fmt.Printf("  Agent write:  %s\n", agentWrite)
	fmt.Printf("  Agent delete: %s\n", agentDelete)
	fmt.Printf("  Human:        ALLOW\n\n")
	fmt.Printf("Source:\n  %s\n", source)
	return nil
}

func explainEnvPolicy(envVar string, cfg *policy.Config, relConfig string) error {
	matchedRule := ""
	agentVis := "PASS"
	source := fmt.Sprintf("environment.mode: %s", cfg.Environment.Mode)

	// Check explicit deny list
	isDenied := false
	for _, d := range cfg.Environment.Deny {
		if envVar == d {
			isDenied = true
			break
		}
	}

	// Check explicit fake list
	isFaked := false
	for _, f := range cfg.Environment.Fake {
		if envVar == f {
			isFaked = true
			break
		}
	}

	// Check explicit allow list
	isAllowed := false
	for _, a := range cfg.Environment.Allow {
		if envVar == a {
			isAllowed = true
			break
		}
	}

	// Check custom capability rules
	for _, r := range cfg.Rules {
		if r.Secret == envVar {
			if r.Read == policy.SecretModeDeny {
				isDenied = true
			} else if r.Read == policy.SecretModeFake {
				isFaked = true
			} else if r.Read == policy.SecretModeAllow {
				isAllowed = true
			}
		}
	}

	// Check privileged sockets
	isPrivileged := false
	for _, p := range policy.PrivilegedIPCEmptyVars {
		if envVar == p {
			isPrivileged = true
			break
		}
	}

	if isPrivileged {
		matchedRule = "privileged local endpoint protection"
		agentVis = "STRIPPED / DENIED"
		source = "built-in privileged IPC isolation"
	} else if isDenied {
		matchedRule = "environment denylist match"
		agentVis = "STRIPPED / DENIED"
		source = fmt.Sprintf("project %s (environment.deny)", relConfig)
	} else if isFaked {
		matchedRule = "environment synthetic virtualization"
		agentVis = "FAKE (format-preserving synthetic value)"
		source = fmt.Sprintf("project %s (environment.fake)", relConfig)
	} else if isAllowed {
		matchedRule = "environment allowlist match"
		agentVis = "PASS (unmodified)"
		source = fmt.Sprintf("project %s (environment.allow)", relConfig)
	} else if cfg.Environment.Mode == policy.EnvModeStrict {
		matchedRule = "environment mode: strict (unlisted variable)"
		agentVis = "STRIPPED / DENIED"
		source = "environment.mode: strict"
	} else if secrets.IsLikelySecretVar(envVar) {
		matchedRule = "sensitive environment pattern (*KEY, *SECRET, *TOKEN, *AUTH, *PASS, DATABASE_*)"
		agentVis = "FAKE (format-preserving synthetic value)"
		source = "built-in environment sanitization"
	} else {
		matchedRule = "standard environment variable"
		agentVis = "PASS (unmodified)"
		source = fmt.Sprintf("environment.mode: %s", cfg.Environment.Mode)
	}

	if !cfg.IsGuardEnabled() {
		agentVis = "PASS (Guard OFF)"
		source = "guard: off (unrestricted host access)"
	}

	fmt.Printf("Resource: %s (Environment Variable)\n\n", envVar)
	fmt.Printf("Matched rule:\n  %s\n\n", matchedRule)
	fmt.Println("Effective access:")
	fmt.Printf("  Agent visibility: %s\n", agentVis)
	fmt.Printf("  Human:            ALLOW (Real value in host shell)\n\n")
	fmt.Printf("Source:\n  %s\n", source)
	return nil
}

func explainNetworkPolicy(host string, cfg *policy.Config, relConfig string) error {
	host = strings.ToLower(strings.TrimSpace(host))

	// Check explicit deny list first
	isDenied := false
	for _, denied := range cfg.Network.Deny {
		if host == denied || strings.HasSuffix(host, "."+denied) {
			isDenied = true
			break
		}
	}

	isAllowed := false
	// Check domain allow list
	for _, allowed := range cfg.Network.Allow {
		if host == allowed || strings.HasSuffix(host, "."+allowed) {
			isAllowed = true
			break
		}
	}

	matchedRule := ""
	agentEgress := "DENIED (HTTP 403 Forbidden)"
	source := fmt.Sprintf("network policy: %s", cfg.Network.Mode)

	if isDenied {
		matchedRule = "domain denylist match"
		agentEgress = "DENIED (HTTP 403 Forbidden)"
		source = fmt.Sprintf("project %s (network.deny)", relConfig)
	} else if isAllowed {
		matchedRule = "domain allowlist match"
		agentEgress = "ALLOWED (filtered via local forward proxy)"
		source = fmt.Sprintf("project %s (network.allow)", relConfig)
	} else if cfg.Network.Mode == policy.NetworkModeAllow {
		matchedRule = "network mode: allow"
		agentEgress = "ALLOWED (unrestricted)"
		source = "network.mode: allow"
	} else {
		matchedRule = "unlisted egress destination"
		agentEgress = "DENIED (HTTP 403 Forbidden)"
		source = fmt.Sprintf("network.mode: %s", cfg.Network.Mode)
	}

	// Check capability injection rules
	capabilityRule := "NONE (transparent TCP tunnel)"
	for _, rule := range cfg.Rules {
		if rule.Use.Enabled {
			for _, h := range rule.Use.Hosts {
				if host == h || strings.HasSuffix(host, "."+h) {
					capabilityRule = fmt.Sprintf("IN-FLIGHT INJECTION (Secret: %s)", rule.Secret)
					break
				}
			}
		}
	}

	if !cfg.IsGuardEnabled() {
		agentEgress = "ALLOWED (Guard OFF)"
		source = "guard: off"
	}

	fmt.Printf("Resource: %s (Network Endpoint)\n\n", host)
	fmt.Printf("Matched rule:\n  %s\n\n", matchedRule)
	fmt.Println("Effective access:")
	fmt.Printf("  Agent egress:   %s\n", agentEgress)
	fmt.Printf("  Credential use: %s\n\n", capabilityRule)
	fmt.Printf("Source:\n  %s\n", source)
	return nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func hasFileExtension(s string) bool {
	ext := strings.ToLower(filepath.Ext(s))
	fileExts := map[string]bool{
		".json": true, ".yaml": true, ".yml": true, ".txt": true,
		".env": true, ".key": true, ".pem": true, ".p12": true,
		".pfx": true, ".toml": true, ".ini": true, ".cfg": true,
		".conf": true, ".xml": true, ".sh": true, ".py": true,
		".js": true, ".ts": true, ".go": true, ".md": true,
		".html": true, ".css": true, ".lock": true, ".sum": true,
		".mod": true,
	}
	return fileExts[ext]
}

func looksLikeDomain(s string) bool {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "localhost" {
		return true
	}
	if strings.HasPrefix(s, ".") || strings.Contains(s, "/") || strings.Contains(s, "\\") {
		return false
	}
	if hasFileExtension(s) {
		return false
	}
	if fileExists(s) {
		return false
	}

	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	tld := parts[len(parts)-1]
	if len(tld) < 2 {
		return false
	}
	for _, r := range tld {
		if !(r >= 'a' && r <= 'z') {
			return false
		}
	}
	return true
}

func isEnvVar(s string) bool {
	if strings.Contains(s, "/") || strings.Contains(s, ".") || strings.Contains(s, "\\") {
		return false
	}
	return s == strings.ToUpper(s) && len(s) > 1
}

func matchPattern(pattern, fullPath, fileName string) bool {
	pattern = filepath.ToSlash(pattern)
	fullPath = filepath.ToSlash(fullPath)
	fileName = filepath.ToSlash(fileName)

	if matched, err := filepath.Match(pattern, fileName); err == nil && matched {
		return true
	}
	if matched, err := filepath.Match(pattern, fullPath); err == nil && matched {
		return true
	}
	clean := strings.TrimSuffix(pattern, "/**")
	clean = strings.TrimSuffix(clean, "/*")
	return strings.HasPrefix(fullPath, clean+"/") || fullPath == clean
}

func matchPathPattern(pattern, absPath, relToCwd, relToHome, fileName, home string, isDir bool) bool {
	pattern = filepath.ToSlash(filepath.Clean(pattern))
	fileName = filepath.ToSlash(fileName)
	cleanAbs := filepath.ToSlash(absPath)
	cleanRelCwd := filepath.ToSlash(relToCwd)
	cleanRelHome := filepath.ToSlash(relToHome)

	cleanPattern := strings.TrimSuffix(pattern, "/**")
	cleanPattern = strings.TrimSuffix(cleanPattern, "/*")

	check := func(cand string) bool {
		if cand == "" {
			return false
		}
		if matched, err := filepath.Match(pattern, cand); err == nil && matched {
			return true
		}
		if matched, err := filepath.Match(cleanPattern, cand); err == nil && matched {
			return true
		}
		if strings.HasPrefix(cand, cleanPattern+"/") || cand == cleanPattern {
			return true
		}
		if isDir && (strings.HasPrefix(cleanPattern, cand+"/") || cleanPattern == cand) {
			return true
		}
		return false
	}

	if check(fileName) {
		return true
	}
	if check(cleanRelCwd) {
		return true
	}
	if check(cleanRelHome) {
		return true
	}
	if check(cleanAbs) {
		return true
	}
	if strings.HasPrefix(pattern, "~/") && home != "" {
		resolvedPattern := filepath.ToSlash(filepath.Join(home, pattern[2:]))
		if check(resolvedPattern) || (isDir && strings.HasPrefix(resolvedPattern, cleanAbs+"/")) {
			return true
		}
	}
	return false
}
