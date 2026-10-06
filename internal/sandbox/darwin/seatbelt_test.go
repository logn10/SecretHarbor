//go:build darwin

package darwin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/secretharbor/secretharbor/internal/compiler"
	"github.com/secretharbor/secretharbor/internal/policy"
)

func TestSeatbeltProfileNetworkRestricted(t *testing.T) {
	plan := &compiler.CompiledPlan{
		ProjectDir: t.TempDir(),
		Network: compiler.NetworkPlan{
			Mode: policy.NetworkModeRestricted,
		},
		Filesystem: compiler.FilesystemPlan{
			Mode: policy.SecretModeAllow,
		},
	}

	sb, err := NewSandbox(plan)
	if err != nil {
		t.Fatalf("NewSandbox failed: %v", err)
	}

	if err := sb.Prepare(plan); err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}

	profile := sb.profileData
	if !strings.Contains(profile, "(deny network-outbound)") {
		t.Errorf("expected profile to deny network-outbound in restricted mode, got:\n%s", profile)
	}
	if !strings.Contains(profile, "(allow network-outbound (remote ip \"localhost:*\"))") {
		t.Errorf("expected profile to allow localhost:* outbound in restricted mode, got:\n%s", profile)
	}
	if !strings.Contains(profile, "(allow network-outbound (remote unix-socket))") {
		t.Errorf("expected profile to allow unix-socket outbound in restricted mode, got:\n%s", profile)
	}
}

func TestSeatbeltProfileNetworkDeny(t *testing.T) {
	plan := &compiler.CompiledPlan{
		ProjectDir: t.TempDir(),
		Network: compiler.NetworkPlan{
			Mode: policy.NetworkModeDeny,
		},
		Filesystem: compiler.FilesystemPlan{
			Mode: policy.SecretModeAllow,
		},
	}

	sb, err := NewSandbox(plan)
	if err != nil {
		t.Fatalf("NewSandbox failed: %v", err)
	}

	if err := sb.Prepare(plan); err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}

	profile := sb.profileData
	if !strings.Contains(profile, "(deny network*)") {
		t.Errorf("expected profile to deny network* in deny mode, got:\n%s", profile)
	}
}

func TestPrepareDetectError(t *testing.T) {
	plan := &compiler.CompiledPlan{
		ProjectDir: filepath.Join(t.TempDir(), "nonexistent_dir"),
		Filesystem: compiler.FilesystemPlan{
			Mode: policy.SecretModeDeny,
		},
	}

	sb, err := NewSandbox(plan)
	if err != nil {
		t.Fatalf("NewSandbox failed: %v", err)
	}

	// Should fail immediately and not ignore error
	if err := sb.Prepare(plan); err == nil {
		t.Errorf("expected Prepare to return error for nonexistent directory, got nil")
	}
}

func TestLaunchNoSandboxArgNotForced(t *testing.T) {
	dir := t.TempDir()
	plan := &compiler.CompiledPlan{
		ProjectDir: dir,
		Filesystem: compiler.FilesystemPlan{
			Mode: policy.SecretModeAllow,
		},
	}

	sb, err := NewSandbox(plan)
	if err != nil {
		t.Fatalf("NewSandbox failed: %v", err)
	}
	if err := sb.Prepare(plan); err != nil {
		t.Fatalf("Prepare failed: %v", err)
	}

	cmd, err := sb.Launch("/Applications/Cursor.app/Contents/MacOS/Cursor", []string{"--test"}, nil)
	if err != nil {
		t.Fatalf("Launch failed: %v", err)
	}

	for _, arg := range cmd.Args {
		if arg == "--no-sandbox" {
			t.Errorf("expected --no-sandbox not to be automatically injected, but found in args: %v", cmd.Args)
		}
	}
}

func TestFailClosedWithoutPrepare(t *testing.T) {
	sb := &DarwinSandbox{
		plan: &compiler.CompiledPlan{
			ProjectDir: os.TempDir(),
		},
		hasSeatbelt: true,
		profileData: "", // Not prepared
	}

	_, err := sb.Launch("/bin/echo", []string{"hello"}, nil)
	if err == nil {
		t.Errorf("expected Launch without profileData to fail closed, got nil")
	}
}
