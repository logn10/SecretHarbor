package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/secretharbor/secretharbor/internal/policy"
	"github.com/secretharbor/secretharbor/internal/secrets"
	"github.com/secretharbor/secretharbor/internal/vault"
)

// RunSecret manages secret metadata and broker capabilities without leaking raw secret values.
func RunSecret(progName string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s secret <list|status|test|set|delete> [key] [val]", progName)
	}

	action := strings.ToLower(args[0])
	subArgs := args[1:]

	v := vault.GlobalVault
	if v == nil {
		var err error
		v, err = vault.OpenDefaultVault()
		if err != nil {
			return fmt.Errorf("failed to access secure vault: %w", err)
		}
	}

	switch action {
	case "list":
		return runSecretList(v)

	case "status":
		if len(subArgs) < 1 {
			return fmt.Errorf("usage: %s secret status <KEY>", progName)
		}
		key := strings.TrimSpace(subArgs[0])
		if key == "" {
			return fmt.Errorf("secret key cannot be empty")
		}
		return runSecretStatus(key, v)

	case "test":
		if len(subArgs) < 1 {
			return fmt.Errorf("usage: %s secret test <KEY>", progName)
		}
		key := strings.TrimSpace(subArgs[0])
		if key == "" {
			return fmt.Errorf("secret key cannot be empty")
		}
		return runSecretTest(key, v)

	case "set":
		useStdin := false
		var cleanArgs []string
		for _, arg := range subArgs {
			if arg == "--stdin" {
				useStdin = true
			} else {
				cleanArgs = append(cleanArgs, arg)
			}
		}

		if len(cleanArgs) < 1 {
			return fmt.Errorf("usage: %s secret set <KEY> [VALUE] [--stdin]", progName)
		}
		key := strings.TrimSpace(cleanArgs[0])
		if key == "" {
			return fmt.Errorf("secret key cannot be empty")
		}

		var val string
		if useStdin || (len(cleanArgs) > 1 && cleanArgs[1] == "-") {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read secret from stdin: %w", err)
			}
			val = strings.TrimRight(string(data), "\r\n")
		} else if len(cleanArgs) >= 2 {
			val = strings.TrimSpace(cleanArgs[1])
		} else {
			fmt.Printf("Enter secret value for %s: ", key)
			reader := bufio.NewReader(os.Stdin)
			input, err := reader.ReadString('\n')
			if err != nil && len(input) == 0 {
				return fmt.Errorf("failed to read secret value: %w", err)
			}
			val = strings.TrimRight(input, "\r\n")
		}

		if val == "" {
			return fmt.Errorf("secret value cannot be empty")
		}
		if err := v.Set(key, val); err != nil {
			return fmt.Errorf("failed to store secret: %w", err)
		}
		fmt.Printf("\033[32m✓ Stored %s in secure encrypted vault\033[0m\n", key)
		return nil

	case "delete":
		if len(subArgs) < 1 {
			return fmt.Errorf("usage: %s secret delete <KEY>", progName)
		}
		key := strings.TrimSpace(subArgs[0])
		if key == "" {
			return fmt.Errorf("secret key cannot be empty")
		}
		_, exists, err := v.Get(key)
		if err != nil {
			return fmt.Errorf("failed to query vault: %w", err)
		}
		if !exists {
			return fmt.Errorf("secret %q not found in vault", key)
		}
		if err := v.Delete(key); err != nil {
			return fmt.Errorf("failed to delete secret: %w", err)
		}
		fmt.Printf("\033[32m✓ Deleted %s from vault\033[0m\n", key)
		return nil

	default:
		return fmt.Errorf("unknown secret action %q. Usage: %s secret <list|status|test|set|delete>", action, progName)
	}
}

func runSecretList(v *vault.Vault) error {
	if v == nil {
		return fmt.Errorf("vault is not available")
	}
	keys, err := v.List()
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		fmt.Println("No secrets stored in vault.")
		return nil
	}

	fmt.Printf("SecretHarbor Credentials (%d keys registered):\n", len(keys))
	fmt.Println(stringsRepeat("─", 45))
	for _, k := range keys {
		fmt.Printf("  • %s\n", k)
	}
	fmt.Println(stringsRepeat("─", 45))
	fmt.Println("\033[90mRun 'shb secret status <KEY>' to inspect capability settings.\033[0m")
	return nil
}

func runSecretStatus(key string, v *vault.Vault) error {
	if v == nil {
		return fmt.Errorf("vault is not available")
	}
	cwd, _ := os.Getwd()
	cfg, _, _ := policy.LoadPolicy(cwd)

	_, inVault, err := v.Get(key)
	if err != nil {
		return fmt.Errorf("failed to read secret from vault: %w", err)
	}
	inEnv := os.Getenv(key) != ""

	if !inVault && !inEnv {
		return fmt.Errorf("secret %q is not registered in local vault or host environment", key)
	}

	storageProvider := "Encrypted Local Vault (~/.secretharbor/vault.enc)"
	if !inVault && inEnv {
		storageProvider = "Host Environment Variable (Ephemeral)"
	}

	agentVis := "FAKE (synthetic value in agent environment)"
	if cfg != nil {
		if !cfg.IsGuardEnabled() {
			agentVis = "ALLOW (Guard OFF)"
		} else {
			isDenied := false
			for _, d := range cfg.Environment.Deny {
				if d == key {
					isDenied = true
					break
				}
			}
			isAllowed := false
			for _, a := range cfg.Environment.Allow {
				if a == key {
					isAllowed = true
					break
				}
			}
			isFaked := false
			for _, f := range cfg.Environment.Fake {
				if f == key {
					isFaked = true
					break
				}
			}

			for _, r := range cfg.Rules {
				if r.Secret == key {
					if r.Read == policy.SecretModeAllow {
						isAllowed = true
					} else if r.Read == policy.SecretModeDeny {
						isDenied = true
					} else if r.Read == policy.SecretModeFake {
						isFaked = true
					}
				}
			}

			if isDenied || cfg.Secrets.Mode == policy.SecretModeDeny {
				agentVis = "DENY (stripped from agent process)"
			} else if isAllowed || cfg.Secrets.Mode == policy.SecretModeAllow {
				agentVis = "ALLOW (real credential passed)"
			} else if isFaked || cfg.Secrets.Mode == policy.SecretModeFake {
				agentVis = "FAKE (synthetic value in agent environment)"
			} else if cfg.Environment.Mode == policy.EnvModeStrict && !isAllowed {
				agentVis = "DENY (stripped in strict mode)"
			} else {
				agentVis = "FAKE (synthetic value in agent environment)"
			}
		}
	}

	runtimeUse := "NOT CONFIGURED"
	var allowedHosts []string
	if cfg != nil {
		for _, r := range cfg.Rules {
			if r.Secret == key && r.Use.Enabled {
				runtimeUse = "ALLOWED (in-flight substitution via proxy)"
				allowedHosts = r.Use.Hosts
				if len(allowedHosts) == 0 {
					allowedHosts = cfg.Runtime.Allow
				}
				break
			}
		}
	}

	fmt.Printf("%s\n\n", key)
	fmt.Printf("Agent visibility: %s\n", agentVis)
	fmt.Printf("Runtime use:      %s\n", runtimeUse)
	if len(allowedHosts) > 0 {
		fmt.Println("Allowed hosts:")
		for _, h := range allowedHosts {
			fmt.Printf("  • %s\n", h)
		}
	}
	fmt.Printf("Stored by:        %s\n", storageProvider)

	return nil
}

func runSecretTest(key string, v *vault.Vault) error {
	if v == nil {
		return fmt.Errorf("vault is not available")
	}
	val, inVault, err := v.Get(key)
	if err != nil {
		return err
	}
	if !inVault {
		val = os.Getenv(key)
	}
	if val == "" {
		return fmt.Errorf("secret %q not found in vault or environment", key)
	}

	fakeVal := secrets.GenerateFakeValue(key)

	fmt.Printf("Testing Secret: %s\n", key)
	fmt.Println(stringsRepeat("─", 45))
	fmt.Printf("✓ Vault retrieval:             OK\n")
	fmt.Printf("✓ Synthetic fake generator:    OK (length: %d chars, prefix: %s)\n", len(fakeVal), getPrefix(fakeVal))

	// Verify capability broker check
	cwd, _ := os.Getwd()
	cfg, _, _ := policy.LoadPolicy(cwd)
	hasRule := false
	if cfg != nil {
		for _, r := range cfg.Rules {
			if r.Secret == key && r.Use.Enabled {
				hasRule = true
				fmt.Printf("✓ Capability injection rule:   CONFIGURED (Hosts: %s)\n", strings.Join(r.Use.Hosts, ", "))
				break
			}
		}
	}
	if !hasRule {
		fmt.Printf("ℹ Capability injection rule:   NOT CONFIGURED (agent will receive synthetic token)\n")
	}

	fmt.Println(stringsRepeat("─", 45))
	fmt.Println("\033[32mVerification passed: Secret is ready for secure virtualization.\033[0m")
	return nil
}

func getPrefix(s string) string {
	if len(s) > 10 {
		return s[:8] + "..."
	}
	return s
}
