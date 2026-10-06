package doctor_test

import (
	"strings"
	"testing"

	"github.com/secretharbor/secretharbor/internal/doctor"
	"github.com/secretharbor/secretharbor/internal/policy"
)

func TestDoctorSuiteRunAll(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &policy.Config{Protection: policy.ProtectionStandard}
	policy.ApplyPresets(cfg)

	suite, err := doctor.NewSuite(tempDir, cfg)
	if err != nil {
		t.Fatalf("failed to create doctor suite: %v", err)
	}

	results := suite.RunAll()
	if len(results) == 0 {
		t.Fatalf("expected test results, got 0")
	}

	if len(results) == 1 && results[0].Name == "Canary Setup" && strings.Contains(results[0].Details, "operation not permitted") {
		t.Skipf("skipping doctor test: running inside outer sandbox restricting canary .env file creation: %s", results[0].Details)
	}

	hasDockerExposure := false
	hasContainerSecrets := false
	hasDockerSocket := false
	hasPolicyTamper := false
	hasFDLeak := false
	hasPtrace := false
	hasEscape := false

	for _, r := range results {
		if r.Name == "DOCKER_HOST Privileged IPC Leakage" {
			hasDockerExposure = true
			if r.Status == doctor.StatusFail {
				t.Errorf("DOCKER_HOST leakage test failed: %s", r.Details)
			}
		}
		if r.Name == "Container Secret Directory Inspection (/run/secrets)" {
			hasContainerSecrets = true
			if r.Status == doctor.StatusFail {
				t.Errorf("container secret inspection test failed: %s", r.Details)
			}
		}
		if r.Name == "Privileged Docker Socket Access" {
			hasDockerSocket = true
			if r.Status == doctor.StatusFail {
				t.Errorf("docker socket test failed: %s", r.Details)
			}
		}
		if r.Name == "Policy File Modification" {
			hasPolicyTamper = true
		}
		if strings.Contains(r.Name, "Sensitive Descriptor Leak") {
			hasFDLeak = true
		}
		if strings.Contains(r.Name, "ptrace") {
			hasPtrace = true
		}
		if strings.Contains(r.Name, "Root Filesystem Escape") {
			hasEscape = true
		}
	}

	if !hasDockerExposure {
		t.Errorf("expected DOCKER_HOST leakage test in results")
	}
	if !hasContainerSecrets {
		t.Errorf("expected container secrets inspection test in results")
	}
	if !hasDockerSocket {
		t.Errorf("expected privileged docker socket access test in results")
	}
	if !hasPolicyTamper {
		t.Errorf("expected Policy File Modification test in results")
	}
	if !hasFDLeak {
		t.Errorf("expected Sensitive Descriptor Leak test in results")
	}
	if !hasPtrace {
		t.Errorf("expected ptrace test in results")
	}
	if !hasEscape {
		t.Errorf("expected Root Filesystem Escape test in results")
	}
}
