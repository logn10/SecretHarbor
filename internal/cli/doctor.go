package cli

import (
	"fmt"
	"os"

	"github.com/secretharbor/secretharbor/internal/doctor"
	"github.com/secretharbor/secretharbor/internal/policy"
)

func RunDoctor(progName string) error {
	fmt.Printf("SecretHarbor Adversarial Security Doctor (via %s)\n", progName)
	fmt.Println("Running live attack test suite...")
	fmt.Println(stringsRepeat("─", 78))

	cwd, _ := os.Getwd()
	cfg, _, err := policy.LoadPolicy(cwd)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}

	suite, err := doctor.NewSuite(cwd, cfg)
	if err != nil {
		return fmt.Errorf("failed to initialize doctor suite: %w", err)
	}

	results := suite.RunAll()

	hasFailure := false
	passCount := 0
	failCount := 0
	limitedCount := 0
	notTestedCount := 0

	for _, r := range results {
		var statusStr string
		switch r.Status {
		case doctor.StatusPass:
			statusStr = "\033[32m[PASS]\033[0m"
			passCount++
		case doctor.StatusFail:
			statusStr = "\033[31m[FAIL]\033[0m"
			failCount++
			hasFailure = true
		case doctor.StatusLimited:
			statusStr = "\033[33m[LIMITED]\033[0m"
			limitedCount++
		default:
			statusStr = "\033[37m[NOT TESTED]\033[0m"
			notTestedCount++
		}

		fmt.Printf("%-16s %-38s %s\n", r.Category, r.Name, statusStr)
		if r.Details != "" {
			fmt.Printf("                 └─ %s\n", r.Details)
		}
	}

	fmt.Println(stringsRepeat("─", 78))
	if hasFailure {
		fmt.Printf("\033[31mDoctor Verification Failed:\033[0m %d passed, %d failed.\n", passCount, failCount)
		return fmt.Errorf("security boundary failed verification")
	}

	fmt.Printf("\033[32mDoctor Verification Passed:\033[0m %d prevented, %d limited, %d not tested.\n", passCount, limitedCount, notTestedCount)
	return nil
}

func stringsRepeat(s string, count int) string {
	var res string
	for i := 0; i < count; i++ {
		res += s
	}
	return res
}
