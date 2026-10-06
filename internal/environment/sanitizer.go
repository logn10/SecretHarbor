package environment

import (
	"strings"

	"github.com/secretharbor/secretharbor/internal/policy"
	"github.com/secretharbor/secretharbor/internal/secrets"
)

// SanitizationResult encapsulates the output of environment filtering.
type SanitizationResult struct {
	FinalEnv     []string          // Clean KEY=VALUE environment for child process
	StrippedVars []string          // Names of variables removed
	FakedVars    map[string]string // Variable name -> Fake value injected
}

// Sanitize processes the current environment against the policy configuration.
func Sanitize(rawEnv []string, cfg *policy.EnvConfig) *SanitizationResult {
	if cfg == nil {
		cfg = &policy.EnvConfig{
			Mode: policy.EnvModeSanitize,
		}
	}

	res := &SanitizationResult{
		FinalEnv:  make([]string, 0),
		FakedVars: make(map[string]string),
	}

	allowMap := make(map[string]bool)
	for _, a := range cfg.Allow {
		allowMap[a] = true
	}

	denyMap := make(map[string]bool)
	for _, d := range cfg.Deny {
		denyMap[d] = true
	}

	fakeMap := make(map[string]bool)
	for _, f := range cfg.Fake {
		fakeMap[f] = true
	}

	// 1. Process existing parent environment
	for _, entry := range rawEnv {
		idx := strings.Index(entry, "=")
		if idx == -1 {
			continue
		}
		key := entry[:idx]
		val := entry[idx+1:]

		// A. Check explicit deny
		if denyMap[key] {
			res.StrippedVars = append(res.StrippedVars, key)
			continue
		}

		// B. Check privileged local IPC variables (always stripped in sanitize mode)
		if isPrivilegedIPCVar(key) {
			res.StrippedVars = append(res.StrippedVars, key)
			continue
		}

		// C. Check if configured to be faked
		if fakeMap[key] {
			fakeVal := secrets.GenerateFakeValue(key)
			res.FakedVars[key] = fakeVal
			res.FinalEnv = append(res.FinalEnv, key+"="+fakeVal)
			continue
		}

		// D. In strict mode or sanitize mode:
		if cfg.Mode == policy.EnvModeStrict {
			if allowMap[key] {
				res.FinalEnv = append(res.FinalEnv, entry)
			} else {
				res.StrippedVars = append(res.StrippedVars, key)
			}
			continue
		}

		// E. In sanitize mode:
		if allowMap[key] {
			res.FinalEnv = append(res.FinalEnv, entry)
		} else if secrets.IsLikelySecretVar(key) {
			// Auto-fake unrecognized sensitive variables
			fakeVal := secrets.GenerateFakeValue(key)
			res.FakedVars[key] = fakeVal
			res.FinalEnv = append(res.FinalEnv, key+"="+fakeVal)
		} else {
			// Safe non-secret variable
			_ = val
			res.FinalEnv = append(res.FinalEnv, entry)
		}
	}

	// 2. Ensure all explicitly configured `fake` variables exist in the final environment
	for _, fakeKey := range cfg.Fake {
		if _, exists := res.FakedVars[fakeKey]; !exists {
			fakeVal := secrets.GenerateFakeValue(fakeKey)
			res.FakedVars[fakeKey] = fakeVal
			res.FinalEnv = append(res.FinalEnv, fakeKey+"="+fakeVal)
		}
	}

	return res
}

func isPrivilegedIPCVar(key string) bool {
	for _, p := range policy.PrivilegedIPCEmptyVars {
		if key == p {
			return true
		}
	}
	return false
}

// MergeEnv merges overrides on top of base environment variables.
// Existing keys are updated in-place; new keys are appended.
// Duplicate keys in base or overrides are properly deduplicated.
func MergeEnv(base []string, overrides []string) []string {
	keyOrder := make([]string, 0)
	valMap := make(map[string]string)

	for _, entry := range base {
		idx := strings.Index(entry, "=")
		if idx == -1 {
			continue
		}
		key := entry[:idx]
		val := entry[idx+1:]
		if _, exists := valMap[key]; !exists {
			keyOrder = append(keyOrder, key)
		}
		valMap[key] = val
	}

	for _, entry := range overrides {
		idx := strings.Index(entry, "=")
		if idx == -1 {
			continue
		}
		key := entry[:idx]
		val := entry[idx+1:]
		if _, exists := valMap[key]; !exists {
			keyOrder = append(keyOrder, key)
		}
		valMap[key] = val
	}

	result := make([]string, 0, len(keyOrder))
	for _, key := range keyOrder {
		result = append(result, key+"="+valMap[key])
	}

	return result
}
