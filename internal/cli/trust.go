package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/secretharbor/secretharbor/internal/policy"
	"gopkg.in/yaml.v3"
)

// RunTrust manages explicitly trusted tools, agents, and processes.
func RunTrust(progName string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: %s trust <list|add|remove> [name]", progName)
	}

	action := strings.ToLower(args[0])
	subArgs := args[1:]

	cwd, _ := os.Getwd()
	cfg, configPath, err := policy.LoadPolicy(cwd)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	if configPath == "" {
		configPath = filepath.Join(cwd, policy.DefaultConfigFileName)
	}

	switch action {
	case "list":
		return runTrustList(cfg)

	case "add":
		if len(subArgs) < 1 {
			return fmt.Errorf("usage: %s trust add <name>", progName)
		}
		name := strings.TrimSpace(subArgs[0])
		if name == "" {
			return fmt.Errorf("process name cannot be empty")
		}
		for _, existing := range cfg.Trusted {
			if strings.EqualFold(existing, name) {
				fmt.Printf("Process %q is already in the trusted list.\n", name)
				return nil
			}
		}
		if err := updateTrustedInYAML(configPath, name, true); err != nil {
			cfg.Trusted = append(cfg.Trusted, name)
			if err := policy.SavePolicyToFile(configPath, cfg); err != nil {
				return fmt.Errorf("failed to update policy: %w", err)
			}
		}
		fmt.Printf("\033[32m✓ Added %q to trusted processes list\033[0m (%s)\n", name, configPath)
		return nil

	case "remove":
		if len(subArgs) < 1 {
			return fmt.Errorf("usage: %s trust remove <name>", progName)
		}
		name := strings.TrimSpace(subArgs[0])
		if name == "" {
			return fmt.Errorf("process name cannot be empty")
		}
		var updated []string
		found := false
		for _, existing := range cfg.Trusted {
			if strings.EqualFold(existing, name) {
				found = true
				continue
			}
			updated = append(updated, existing)
		}
		if !found {
			return fmt.Errorf("process %q not found in trusted list", name)
		}
		if err := updateTrustedInYAML(configPath, name, false); err != nil {
			cfg.Trusted = updated
			if err := policy.SavePolicyToFile(configPath, cfg); err != nil {
				return fmt.Errorf("failed to update policy: %w", err)
			}
		}
		fmt.Printf("\033[32m✓ Removed %q from trusted processes list\033[0m\n", name)
		return nil

	default:
		return fmt.Errorf("unknown trust command %q. Usage: %s trust <list|add|remove> [name]", action, progName)
	}
}

func updateTrustedInYAML(configPath string, name string, add bool) error {
	data, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if len(strings.TrimSpace(string(data))) == 0 {
		var initialTrusted []string
		if add {
			initialTrusted = []string{name}
		}
		newCfg := &policy.Config{
			Version:    1,
			Protection: policy.ProtectionStandard,
			Trusted:    initialTrusted,
		}
		return policy.SavePolicyToFile(configPath, newCfg)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}

	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		newCfg := &policy.Config{
			Version:    1,
			Protection: policy.ProtectionStandard,
		}
		if add {
			newCfg.Trusted = []string{name}
		}
		return policy.SavePolicyToFile(configPath, newCfg)
	}

	mapping := root.Content[0]
	var trustedValNode *yaml.Node
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == "trusted" {
			trustedValNode = mapping.Content[i+1]
			break
		}
	}

	if add {
		if trustedValNode == nil {
			keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "trusted"}
			valNode := &yaml.Node{
				Kind:    yaml.SequenceNode,
				Content: []*yaml.Node{{Kind: yaml.ScalarNode, Value: name}},
			}
			mapping.Content = append(mapping.Content, keyNode, valNode)
		} else if trustedValNode.Kind == yaml.SequenceNode {
			for _, item := range trustedValNode.Content {
				if strings.EqualFold(item.Value, name) {
					return nil // already present
				}
			}
			trustedValNode.Content = append(trustedValNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: name})
		}
	} else {
		if trustedValNode != nil && trustedValNode.Kind == yaml.SequenceNode {
			var filtered []*yaml.Node
			for _, item := range trustedValNode.Content {
				if !strings.EqualFold(item.Value, name) {
					filtered = append(filtered, item)
				}
			}
			trustedValNode.Content = filtered
		}
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return err
	}
	_ = enc.Close()

	return policy.AtomicWriteFile(configPath, buf.Bytes(), 0600)
}

func runTrustList(cfg *policy.Config) error {
	if len(cfg.Trusted) == 0 {
		fmt.Println("No explicitly trusted tools or processes configured.")
		fmt.Println("All agent child processes run under standard sandbox restrictions.")
		return nil
	}

	fmt.Printf("SecretHarbor Trusted Processes (%d configured):\n", len(cfg.Trusted))
	fmt.Println(stringsRepeat("─", 45))
	for _, t := range cfg.Trusted {
		fmt.Printf("  • %s\n", t)
	}
	fmt.Println(stringsRepeat("─", 45))
	fmt.Println("\033[33mNote:\033[0m trusted entries are advisory metadata; they do not currently alter sandbox enforcement.")
	return nil
}
