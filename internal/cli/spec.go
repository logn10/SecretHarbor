package cli

import (
	"fmt"
	"strings"
)

// FlagDef describes a CLI flag or option.
type FlagDef struct {
	Name        string
	Shorthand   string
	Description string
	Default     string
}

// CommandDef describes a CLI command, its synopsis, subcommands, and options.
type CommandDef struct {
	Name        string
	Summary     string
	Usage       string
	Description string
	Examples    []string
	Flags       []FlagDef
	Subcommands map[string]*CommandDef
}

// CommandRegistry is the central source of truth for all SecretHarbor CLI commands.
var CommandRegistry = map[string]*CommandDef{
	"init": {
		Name:        "init",
		Summary:     "Initialize SecretHarbor host integration and project policy",
		Usage:       "init [path] [--yes] [--force]",
		Description: "Configures SecretHarbor host-level security for the current project. Automatically discovers supported AI agents (Claude Code, Codex, Gemini CLI, Aider, Cline) and desktop environments (Cursor, VS Code), installs transparent launcher shims (~/.secretharbor/shims), configures shell profile PATH (~/.zshrc, ~/.bashrc), scans for running agent processes, and initializes secretharbor.yaml if not present. Shims persist across system reboots.",
		Flags: []FlagDef{
			{Name: "yes", Shorthand: "y", Description: "Automatically restart unprotected running agents without interactive confirmation"},
			{Name: "force", Shorthand: "f", Description: "Overwrite existing secretharbor.yaml with current default template"},
		},
		Examples: []string{
			"shb init",
			"shb init --yes",
			"shb init --force",
			"shb init ./my-project/secretharbor.yaml",
		},
	},
	"adopt": {
		Name:        "adopt",
		Summary:     "Discover and adopt unprotected running agents",
		Usage:       "adopt [--yes]",
		Description: "Scans for currently running agent processes that were started before SecretHarbor was active. Because active processes cannot be retroactively sandboxed safely without an established OS security boundary, 'shb adopt' safely terminates them (SIGTERM -> SIGKILL) and restarts them inside a fresh SecretHarbor sandbox.",
		Flags: []FlagDef{
			{Name: "yes", Shorthand: "y", Description: "Automatically restart unprotected agents without interactive confirmation"},
		},
		Examples: []string{
			"shb adopt",
			"shb adopt --yes",
		},
	},
	"restart": {
		Name:        "restart",
		Summary:     "Cleanly restart an agent inside a fresh sandbox",
		Usage:       "restart [agent]",
		Description: "Stops an active SecretHarbor agent session (or terminates an unprotected running agent process) and restarts it immediately inside a freshly initialized, fully enforced OS sandbox.",
		Examples: []string{
			"shb restart claude",
			"shb restart codex",
			"shb restart",
		},
	},
	"run": {
		Name:        "run",
		Summary:     "Explicitly run an agent inside the security boundary (debug/fallback)",
		Usage:       "run <agent> [args...] | run -- <command...>",
		Description: "Executes an AI agent or arbitrary command inside an OS-enforced security sandbox with secret virtualization, environment sanitization, and network proxying. Note: After 'shb init', agents (e.g. claude, codex, gemini) automatically run guarded when launched directly. 'shb run' provides an explicit invocation path and debugging fallback. Unrecognized binaries and arbitrary commands default to Runtime: process, Integration: unknown and are always confined under standard sandbox protections (Universal Untrusted Fallback Invariant). SecretHarbor enforces a strict fail-closed invariant: if the security boundary cannot be established, the agent is refused launch.",
		Examples: []string{
			"shb run claude",
			"shb run gemini",
			"shb run codex",
			"shb run cursor",
			"shb run -- npm test",
			"shb run -- /bin/sh -c \"pytest\"",
		},
	},
	"status": {
		Name:        "status",
		Summary:     "Show active protection and enforcement status",
		Usage:       "status",
		Description: "Displays comprehensive SecretHarbor host integration and enforcement status, including persistent launcher shims, shell PATH configuration, active sandboxes, process hierarchy with security boundary demarcation, Docker capability mode, secret virtualization, network isolation, active protected sessions, and any detected unprotected agent processes.",
		Examples: []string{
			"shb status",
		},
	},
	"sessions": {
		Name:        "sessions",
		Summary:     "List active SecretHarbor sessions",
		Usage:       "sessions",
		Description: "Lists all currently active SecretHarbor-managed agent sessions across projects with their session IDs, agent types, and process PIDs.",
		Examples: []string{
			"shb sessions",
		},
	},
	"stop": {
		Name:        "stop",
		Summary:     "Stop a guarded agent session",
		Usage:       "stop [session-id]",
		Description: "Cleanly terminates the agent process tree and cleans up temporary sandbox/proxy state. Crucially, stopping an agent session never weakens or alters the SecretHarbor security policy.",
		Examples: []string{
			"shb stop",
			"shb stop a81f",
		},
	},
	"doctor": {
		Name:        "doctor",
		Summary:     "Run adversarial security verification test suite",
		Usage:       "doctor",
		Description: "Executes a 14-vector adversarial attack suite verifying that direct file reads, interpreter reads, symlinks, path traversals, file copies, environment variables, privileged sockets, Docker socket access, container secret directories (/run/secrets), DOCKER_HOST leakage, and policy files cannot be exploited by the agent.",
		Examples: []string{
			"shb doctor",
		},
	},
	"config": {
		Name:        "config",
		Summary:     "Inspect and manage effective policy configuration",
		Usage:       "config [show|check|edit|diff|source] [options]",
		Description: "Inspects what SecretHarbor intends to enforce. `shb config` and `shb config show` are strictly read-only and never print secret values. `shb config edit` is a human-only operation protected against agent execution.",
		Subcommands: map[string]*CommandDef{
			"show": {
				Name:        "show",
				Summary:     "Show effective policy configuration (read-only)",
				Usage:       "config show [--json]",
				Description: "Displays the effective policy with all defaults, presets, and overrides resolved. Never reveals secret credentials.",
				Flags: []FlagDef{
					{Name: "json", Description: "Output in machine-readable JSON format"},
				},
				Examples: []string{
					"shb config",
					"shb config show",
					"shb config --json",
				},
			},
			"get": {
				Name:        "get",
				Summary:     "Get a policy configuration setting value",
				Usage:       "config get <key>",
				Description: "Reads and displays the current configuration value for a specified key (e.g. protection, guard, secrets.mode, network.mode).",
				Examples: []string{
					"shb config get protection",
					"shb config get guard",
					"shb config get secrets.mode",
				},
			},
			"set": {
				Name:        "set",
				Summary:     "Set a policy configuration setting value (human-only)",
				Usage:       "config set <key> <value>",
				Description: "Updates and validates a configuration setting in project policy file. Sandboxed agents are denied execution.",
				Examples: []string{
					"shb config set protection strict",
					"shb config set secrets.mode fake",
					"shb config set network.mode deny",
				},
			},
			"source": {
				Name:        "source",
				Summary:     "Trace where each effective rule originated",
				Usage:       "config source",
				Description: "Displays rule provenance and lineage, showing whether a rule originated from a preset, built-in detection, or project file override.",
				Examples: []string{
					"shb config source",
				},
			},
			"check": {
				Name:        "check",
				Summary:     "Validate policy syntax and consistency",
				Usage:       "config check",
				Description: "Checks the project policy file for YAML syntax errors, rule contradictions, and invalid presets.",
				Examples: []string{
					"shb config check",
				},
			},
			"edit": {
				Name:        "edit",
				Summary:     "Edit project policy in trusted editor (human-only)",
				Usage:       "config edit",
				Description: "Opens the project policy in $EDITOR. Protected by a strict security boundary: sandboxed agents are denied execution to prevent policy tampering.",
				Examples: []string{
					"shb config edit",
				},
			},
			"diff": {
				Name:        "diff",
				Summary:     "Show diff between project policy and standard preset",
				Usage:       "config diff",
				Description: "Visualizes the customizations in the current project compared to SecretHarbor's base standard security preset.",
				Examples: []string{
					"shb config diff",
				},
			},
		},
		Examples: []string{
			"shb config",
			"shb config --json",
			"shb config source",
			"shb config check",
			"shb config edit",
			"shb config diff",
		},
	},
	"policy": {
		Name:        "policy",
		Summary:     "Policy validation and resource decision explanation",
		Usage:       "policy <check|explain> [resource]",
		Description: "Validate policy or debug security decisions for specific files, environment variables, or network domains.",
		Subcommands: map[string]*CommandDef{
			"check": {
				Name:        "check",
				Summary:     "Validate the current policy file",
				Usage:       "policy check",
				Description: "Validates the active policy file and reports its effective settings.",
				Examples: []string{
					"shb policy check",
				},
			},
			"explain": {
				Name:        "explain",
				Summary:     "Explain security policy decisions for a resource",
				Usage:       "policy explain <resource>",
				Description: "Answers 'Why was this operation denied, faked, or allowed?' Details matched rule, effective agent access vs human access, and rule origin.",
				Examples: []string{
					"shb policy explain .env",
					"shb policy explain DATABASE_URL",
					"shb policy explain ~/.ssh/id_ed25519",
					"shb policy explain --network api.stripe.com",
				},
			},
		},
		Examples: []string{
			"shb policy check",
			"shb policy explain .env",
			"shb policy explain DATABASE_URL",
			"shb policy explain --network api.stripe.com",
		},
	},
	"secret": {
		Name:        "secret",
		Summary:     "Manage credentials and broker capabilities",
		Usage:       "secret <list|status|test|set|delete> [key] [val]",
		Description: "Inspects capability states, allowed hosts, and vault metadata. Intentionally does NOT provide commands to reveal or dump raw secret values.",
		Subcommands: map[string]*CommandDef{
			"list": {
				Name:        "list",
				Summary:     "List stored credential keys",
				Usage:       "secret list",
				Description: "Lists all secret keys currently registered in the encrypted local vault or policy broker.",
				Examples: []string{
					"shb secret list",
				},
			},
			"status": {
				Name:        "status",
				Summary:     "Show capability and virtualization status for a secret",
				Usage:       "secret status <KEY>",
				Description: "Displays agent visibility, runtime capability injection state, allowed outbound hosts, and storage provider without revealing secret contents.",
				Examples: []string{
					"shb secret status DATABASE_URL",
					"shb secret status STRIPE_KEY",
				},
			},
			"test": {
				Name:        "test",
				Summary:     "Verify secret format and capability injection rules",
				Usage:       "secret test <KEY>",
				Description: "Validates presence in the local vault, tests synthetic fake value generation, and checks broker routing.",
				Examples: []string{
					"shb secret test STRIPE_KEY",
				},
			},
			"set": {
				Name:        "set",
				Summary:     "Store a credential in the local encrypted vault",
				Usage:       "secret set <KEY> <VAL>",
				Description: "Encrypts and stores a credential in AES-256-GCM vault with strict file permissions.",
				Examples: []string{
					"shb secret set STRIPE_KEY sk_live_...",
				},
			},
			"delete": {
				Name:        "delete",
				Summary:     "Remove a credential from the vault",
				Usage:       "secret delete <KEY>",
				Description: "Deletes a credential from the encrypted local vault.",
				Examples: []string{
					"shb secret delete STRIPE_KEY",
				},
			},
		},
		Examples: []string{
			"shb secret list",
			"shb secret status DATABASE_URL",
			"shb secret test STRIPE_KEY",
			"shb secret set STRIPE_KEY sk_live_...",
			"shb secret delete STRIPE_KEY",
		},
	},
	"trust": {
		Name:        "trust",
		Summary:     "Manage the advisory trusted process list (not yet enforced)",
		Usage:       "trust <list|add|remove> [name]",
		Description: "Maintains an advisory list of trusted tools, MCP servers, and processes. Entries are metadata only and do not currently change sandbox enforcement.",
		Subcommands: map[string]*CommandDef{
			"list": {
				Name:        "list",
				Summary:     "List all explicitly trusted tools and processes",
				Usage:       "trust list",
				Description: "Lists all processes and tools currently recognized as trusted in the project policy.",
				Examples: []string{
					"shb trust list",
				},
			},
			"add": {
				Name:        "add",
				Summary:     "Add a trusted tool or process",
				Usage:       "trust add <name>",
				Description: "Records a tool, executable, or MCP server as trusted in the advisory list (not yet enforced).",
				Examples: []string{
					"shb trust add git",
					"shb trust add npm",
					"shb trust add mcp-github-server",
				},
			},
			"remove": {
				Name:        "remove",
				Summary:     "Remove a trusted tool or process",
				Usage:       "trust remove <name>",
				Description: "Revokes trusted status from an agent or process.",
				Examples: []string{
					"shb trust remove npm",
				},
			},
		},
		Examples: []string{
			"shb trust list",
			"shb trust add git",
			"shb trust remove git",
		},
	},
	"guard": {
		Name:        "guard",
		Summary:     "Enable or explicitly disable protection for this project",
		Usage:       "guard <on|off>",
		Description: "Control project guard state. Disabling protection requires explicit interactive confirmation to prevent accidental exposure.",
		Subcommands: map[string]*CommandDef{
			"on": {
				Name:        "on",
				Summary:     "Enable SecretHarbor protection",
				Usage:       "guard on",
				Description: "Re-enables sandbox confinement, secret virtualization, and network policy for this project.",
				Examples: []string{
					"shb guard on",
				},
			},
			"off": {
				Name:        "off",
				Summary:     "Disable SecretHarbor protection (requires confirmation)",
				Usage:       "guard off [--yes]",
				Description: "Explicitly disables protection for this project. Prompts with a warning detailing the security consequences.",
				Flags: []FlagDef{
					{Name: "yes", Shorthand: "y", Description: "Bypass interactive confirmation prompt"},
				},
				Examples: []string{
					"shb guard off",
					"shb guard off --yes",
				},
			},
		},
		Examples: []string{
			"shb guard on",
			"shb guard off",
		},
	},
	"version": {
		Name:        "version",
		Summary:     "Show SecretHarbor version and security subsystem details",
		Usage:       "version",
		Description: "Displays the SecretHarbor version, platform, OS kernel, active sandbox driver, and policy specification version.",
		Examples: []string{
			"shb version",
			"shb --version",
			"shb -v",
		},
	},
	"update": {
		Name:        "update",
		Summary:     "Check for and install SecretHarbor updates",
		Usage:       "update [--check] [--version <ver>] [--dry-run] [--json]",
		Description: "Checks for and installs a newer SecretHarbor CLI and runtime version. Does not alter project security policy. Features cryptographic checksum and signature verification, atomic replacement with automatic rollback, and agent lockout protection.",
		Examples: []string{
			"shb update",
			"shb update --check",
			"shb update --version 0.4.0",
			"shb update --dry-run",
		},
		Flags: []FlagDef{
			{Name: "check", Shorthand: "c", Description: "Check for newer versions without installing"},
			{Name: "version", Shorthand: "v", Description: "Target a specific release version"},
			{Name: "dry-run", Shorthand: "n", Description: "Simulate download and signature verification without replacing binary"},
			{Name: "json", Shorthand: "j", Description: "Output update check results in JSON format"},
		},
	},
	"restore": {
		Name:        "restore",
		Summary:     "Restore swapped secret files to their original real values",
		Usage:       "restore [path] [--all] [--orphans]",
		Description: "Restores project secret files (.env) from the secure vault backup back to their original disk locations. Safely performs 3-way reconciliation so that newly added configuration keys and edited variables are preserved while real secrets are restored.",
		Flags: []FlagDef{
			{Name: "all", Shorthand: "a", Description: "Restore swapped secret files across all registered projects"},
			{Name: "orphans", Shorthand: "o", Description: "Restore orphaned swaps left by crashed or terminated processes"},
		},
		Examples: []string{
			"shb restore",
			"shb restore --all",
			"shb restore --orphans",
			"shb restore /path/to/project",
		},
	},
	"env": {
		Name:        "env",
		Summary:     "Manage environment and live secret updates",
		Usage:       "env [edit]",
		Description: "Provides safe live editing of environment secrets. During active agent sessions, 'shb env edit' opens the real backup in $EDITOR and automatically refreshes the in-tree synthetic file for the active session without exposing secrets to the sandboxed agent.",
		Examples: []string{
			"shb env edit",
		},
	},
	"help": {
		Name:        "help",
		Summary:     "Show CLI documentation",
		Usage:       "help [command]",
		Description: "Displays general usage or command-specific reference manual.",
		Examples: []string{
			"shb help",
			"shb help run",
			"shb help config",
			"shb help policy",
			"shb help doctor",
		},
	},
}

// RenderHelp formats top-level or command-specific interactive help.
func RenderHelp(progName string, cmdName string) string {
	if cmdName == "" || cmdName == "help" {
		alias := "secretharbor"
		if progName == "secretharbor" {
			alias = "shb"
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("SecretHarbor — Host-level security boundary for AI agents (v%s)\n\n", Version))
		b.WriteString("Usage:\n")
		b.WriteString(fmt.Sprintf("  %s <command> [arguments]\n", progName))
		b.WriteString(fmt.Sprintf("  (alias: %s <command> [arguments])\n\n", alias))
		b.WriteString("Commands:\n")

		primaryCmds := []string{
			"init", "adopt", "restart", "run", "status", "sessions", "stop", "config", "policy", "secret", "env", "restore", "trust", "doctor", "guard", "update", "version", "help",
		}

		for _, name := range primaryCmds {
			cmd, exists := CommandRegistry[name]
			if exists {
				b.WriteString(fmt.Sprintf("  %-16s  %s\n", cmd.Name, cmd.Summary))
			}
		}

		b.WriteString("\nExamples:\n")
		b.WriteString(fmt.Sprintf("  %s init\n", progName))
		b.WriteString(fmt.Sprintf("  %s adopt\n", progName))
		b.WriteString(fmt.Sprintf("  %s restart claude\n", progName))
		b.WriteString(fmt.Sprintf("  %s run claude\n", progName))
		b.WriteString(fmt.Sprintf("  %s status\n", progName))
		b.WriteString(fmt.Sprintf("  %s config\n", progName))
		b.WriteString(fmt.Sprintf("  %s policy explain .env\n", progName))
		b.WriteString(fmt.Sprintf("  %s doctor\n", progName))

		b.WriteString("\nUse:\n")
		b.WriteString(fmt.Sprintf("  %s help <command>       Show command-specific documentation\n", progName))
		b.WriteString("\nWebsite:\n")
		b.WriteString("  https://secretharbor.dev\n")
		return b.String()
	}

	cmd, exists := CommandRegistry[cmdName]
	if !exists {
		return fmt.Sprintf("Unknown command: %s. Run '%s help' for available commands.\n", cmdName, progName)
	}

	var b strings.Builder
	b.WriteString(fmt.Sprintf("NAME\n    %s %s - %s\n\n", progName, cmd.Name, cmd.Summary))
	b.WriteString(fmt.Sprintf("USAGE\n    %s %s\n\n", progName, cmd.Usage))
	b.WriteString(fmt.Sprintf("DESCRIPTION\n    %s\n\n", cmd.Description))

	if len(cmd.Subcommands) > 0 {
		b.WriteString("SUBCOMMANDS\n")
		for subName, subCmd := range cmd.Subcommands {
			b.WriteString(fmt.Sprintf("    %-18s %s\n", subName, subCmd.Summary))
		}
		b.WriteString("\n")
	}

	if len(cmd.Flags) > 0 {
		b.WriteString("OPTIONS\n")
		for _, f := range cmd.Flags {
			if f.Shorthand != "" {
				b.WriteString(fmt.Sprintf("    -%s, --%-14s %s\n", f.Shorthand, f.Name, f.Description))
			} else {
				b.WriteString(fmt.Sprintf("    --%-18s %s\n", f.Name, f.Description))
			}
		}
		b.WriteString("\n")
	}

	if len(cmd.Examples) > 0 {
		b.WriteString("EXAMPLES\n")
		for _, ex := range cmd.Examples {
			// Replace default 'shb' with actual progName if different
			customEx := strings.Replace(ex, "shb ", progName+" ", 1)
			b.WriteString(fmt.Sprintf("    $ %s\n", customEx))
		}
		b.WriteString("\n")
	}

	return b.String()
}
