package docs

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

func getDocDate() string {
	if epochStr := os.Getenv("SOURCE_DATE_EPOCH"); epochStr != "" {
		if epoch, err := strconv.ParseInt(epochStr, 10, 64); err == nil {
			return time.Unix(epoch, 0).UTC().Format("January 2006")
		}
	}
	return "October 2026"
}

// GenerateMainManPage creates the primary shb(1) manual page in roff format.
func GenerateMainManPage() string {
	dateStr := getDocDate()
	var b strings.Builder

	b.WriteString(fmt.Sprintf(".TH SHB 1 %q %q \"SecretHarbor Manual\"\n", dateStr, "SecretHarbor "+Version))
	b.WriteString(".SH NAME\n")
	b.WriteString("shb \\- security layer for AI agents\n")
	b.WriteString(".SH SYNOPSIS\n")
	b.WriteString("\\fBshb\\fR [\\fIcommand\\fR] [\\fIoptions\\fR]\n")
	b.WriteString(".SH DESCRIPTION\n")
	b.WriteString("SecretHarbor creates an OS-enforced security boundary around AI agents and their child processes.\n")
	b.WriteString("It protects real secrets (.env, cloud keys, database credentials, SSH private keys) by\n")
	b.WriteString("transparently virtualizing them with synthetic fakes and isolating network and IPC endpoints.\n")
	b.WriteString(".SH COMMANDS\n")

	primaryCmds := []string{
		"init", "adopt", "restart", "run", "status", "sessions", "stop", "config", "policy", "secret", "env", "restore", "trust", "doctor", "guard", "update", "version", "help",
	}

	for _, name := range primaryCmds {
		cmd, exists := CommandRegistry[name]
		if !exists {
			continue
		}
		b.WriteString(".TP\n")
		b.WriteString(fmt.Sprintf("\\fB%s\\fR\n", cmd.Name))
		b.WriteString(fmt.Sprintf("%s\n", cmd.Summary))
	}

	b.WriteString(".SH SECURITY\n")
	b.WriteString("The agent cannot modify the active SecretHarbor policy or disable its own security boundary.\n")
	b.WriteString("File operations outside the authorized workspace and unapproved capability escalations are denied by the kernel.\n")
	b.WriteString(".SH EXAMPLES\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fBshb init\\fR\n")
	b.WriteString("Initialize host integration, detect agents, and install persistent launcher shims\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fBshb adopt\\fR\n")
	b.WriteString("Discover unprotected running agents and restart them under SecretHarbor\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fBshb restart claude\\fR\n")
	b.WriteString("Cleanly restart Claude Code inside a fresh SecretHarbor sandbox\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fBshb status\\fR\n")
	b.WriteString("Show host integration, active protected sessions, and unprotected processes\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fBshb config\\fR\n")
	b.WriteString("Inspect effective configuration without exposing secret values\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fBshb policy explain .env\\fR\n")
	b.WriteString("Explain why .env is faked or denied\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fBshb doctor\\fR\n")
	b.WriteString("Run live 14-vector adversarial attack tests\n")
	b.WriteString(".SH FILES\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fIsecretharbor.yaml\\fR\n")
	b.WriteString("Project security policy configuration.\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fI~/.secretharbor/shims\\fR\n")
	b.WriteString("Transparent agent launcher shims.\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fI~/.secretharbor/vault.enc\\fR\n")
	b.WriteString("AES-256-GCM encrypted local credential vault.\n")
	b.WriteString(".TP\n")
	b.WriteString("\\fI~/.secretharbor/audit.log\\fR\n")
	b.WriteString("Redacted security audit trail.\n")
	b.WriteString(".SH SEE ALSO\n")
	b.WriteString("shb-init(1), shb-adopt(1), shb-restart(1), shb-run(1), shb-status(1), shb-sessions(1), shb-stop(1), shb-config(1), shb-policy(1), shb-secret(1), shb-env(1), shb-restore(1), shb-trust(1), shb-doctor(1), shb-guard(1), shb-update(1), shb-version(1), shb-help(1)\n")
	b.WriteString(".SH WEBSITE\n")
	b.WriteString("https://secretharbor.dev\n")

	return b.String()
}

// GenerateCommandManPage creates a command-specific man page (e.g. shb-run.1) in roff format.
func GenerateCommandManPage(cmdName string) (string, error) {
	cmd, exists := CommandRegistry[cmdName]
	if !exists {
		return "", fmt.Errorf("command %s not found in registry", cmdName)
	}

	dateStr := getDocDate()
	pageTitle := fmt.Sprintf("SHB-%s", strings.ToUpper(cmdName))
	docName := fmt.Sprintf("shb-%s", cmdName)

	var b strings.Builder
	b.WriteString(fmt.Sprintf(".TH %s 1 %q %q \"SecretHarbor Manual\"\n", pageTitle, dateStr, "SecretHarbor "+Version))
	b.WriteString(".SH NAME\n")
	b.WriteString(fmt.Sprintf("%s \\- %s\n", docName, cmd.Summary))
	b.WriteString(".SH SYNOPSIS\n")
	b.WriteString(fmt.Sprintf("\\fBshb %s\\fR\n", cmd.Usage))
	b.WriteString(".SH DESCRIPTION\n")
	b.WriteString(fmt.Sprintf("%s\n", cmd.Description))

	if len(cmd.Subcommands) > 0 {
		b.WriteString(".SH SUBCOMMANDS\n")
		subNames := make([]string, 0, len(cmd.Subcommands))
		for subName := range cmd.Subcommands {
			subNames = append(subNames, subName)
		}
		sort.Strings(subNames)
		for _, subName := range subNames {
			subCmd := cmd.Subcommands[subName]
			b.WriteString(".TP\n")
			b.WriteString(fmt.Sprintf("\\fB%s\\fR\n", subName))
			b.WriteString(fmt.Sprintf("%s\n", subCmd.Description))
		}
	}

	if len(cmd.Flags) > 0 {
		b.WriteString(".SH OPTIONS\n")
		for _, f := range cmd.Flags {
			b.WriteString(".TP\n")
			if f.Shorthand != "" {
				b.WriteString(fmt.Sprintf("\\fB-%s\\fR, \\fB--%s\\fR\n", f.Shorthand, f.Name))
			} else {
				b.WriteString(fmt.Sprintf("\\fB--%s\\fR\n", f.Name))
			}
			b.WriteString(fmt.Sprintf("%s\n", f.Description))
		}
	}

	if len(cmd.Examples) > 0 {
		b.WriteString(".SH EXAMPLES\n")
		for _, ex := range cmd.Examples {
			b.WriteString(".TP\n")
			b.WriteString(fmt.Sprintf("$ \\fB%s\\fR\n", ex))
		}
	}

	b.WriteString(".SH SEE ALSO\n")
	b.WriteString("shb(1)\n")
	b.WriteString(".SH WEBSITE\n")
	b.WriteString("https://secretharbor.dev\n")

	return b.String(), nil
}
