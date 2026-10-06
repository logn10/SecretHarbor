package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/secretharbor/secretharbor/internal/updater"
)

// RunUpdate handles `shb update` and all its flags (--check, --version, --dry-run, --json).
func RunUpdate(progName string, args []string) error {
	// First check: Agent Lockout
	if err := updater.CheckAgentLockout(); err != nil {
		return err
	}

	checkOnly := false
	isJSON := false
	dryRun := false
	targetVersion := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--check", "-c":
			checkOnly = true
		case "--json", "-j":
			isJSON = true
		case "--dry-run", "-n":
			dryRun = true
		case "--version", "-v":
			if i+1 < len(args) {
				targetVersion = args[i+1]
				i++
			} else {
				return fmt.Errorf("missing version argument for --version flag")
			}
		default:
			if strings.HasPrefix(arg, "-") {
				return fmt.Errorf("unknown update flag %q. Usage: %s update [--check] [--version <ver>] [--dry-run] [--json]", arg, progName)
			}
			// Allow direct positional version: shb update 0.3.0
			if targetVersion == "" {
				targetVersion = arg
			}
		}
	}

	if checkOnly {
		return runUpdateCheck(progName, targetVersion, isJSON)
	}

	return runUpdateApply(progName, targetVersion, dryRun, isJSON)
}

func runUpdateCheck(progName string, targetVersion string, isJSON bool) error {
	check, err := updater.CheckForUpdate(Version, targetVersion)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	if isJSON {
		data, _ := json.MarshalIndent(check, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	fmt.Printf("SecretHarbor %s\n\n", check.CurrentVersion)
	fmt.Printf("Latest version: %s\n", check.LatestVersion)

	if check.UpdateAvailable {
		fmt.Printf("\033[32mUpdate available.\033[0m\n\n")
		fmt.Println("Run:")
		if targetVersion != "" {
			fmt.Printf("  %s update --version %s\n", progName, targetVersion)
		} else {
			fmt.Printf("  %s update\n", progName)
		}
	} else {
		fmt.Printf("SecretHarbor is up to date.\n")
	}

	return nil
}

func runUpdateApply(progName string, targetVersion string, dryRun bool, isJSON bool) error {
	res, err := updater.ApplyUpdate(Version, targetVersion, dryRun)
	if err != nil {
		return err
	}

	if isJSON {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return nil
	}

	if res.PreviousVersion == res.CurrentVersion && !res.DryRun {
		fmt.Printf("SecretHarbor %s is already up to date.\n", res.CurrentVersion)
		return nil
	}

	if res.DryRun {
		fmt.Printf("SecretHarbor update simulation successful.\n\n")
		fmt.Printf("Target version:  %s\n", res.CurrentVersion)
		fmt.Printf("Signature:       %s\n", res.SignatureStatus)
		fmt.Println("\nRun without --dry-run to apply.")
		return nil
	}

	fmt.Println("SecretHarbor updated successfully.")
	fmt.Println()
	fmt.Printf("Previous version: %s\n", res.PreviousVersion)
	fmt.Printf("Current version:  %s\n", res.CurrentVersion)
	fmt.Printf("Signature:        %s\n", res.SignatureStatus)
	return nil
}
