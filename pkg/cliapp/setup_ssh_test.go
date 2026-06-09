package cliapp

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// setupSSHRoot mounts setup-ssh on a root sharing the addHostFixture runtime
// (HOME-tmpdir, tmpdir-rooted ssh.conf writer).
func setupSSHRoot(f *addHostFixture) *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	root.SetOut(f.stdout)
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.AddCommand(setupSSHCommand(f.rt))
	return root
}

// TestSetupSSHPrependsInclude verifies the Include lands as the FIRST line of
// ~/.ssh/config, ahead of any Host block, preserving prior content below it.
func TestSetupSSHPrependsInclude(t *testing.T) {
	f := newAddHostFixture(t)
	existing := "# my notes\nHost solo\n  HostName 10.0.0.2\n"
	f.writeSSHConfig(t, existing)

	if err := execute(context.Background(), setupSSHRoot(f), "setup-ssh"); err != nil {
		t.Fatalf("Run(setup-ssh) error = %v", err)
	}

	data, _ := f.readSSHConfig(t)
	got := string(data)
	want := "Include ~/.postern/ssh.conf\n" + existing
	if got != want {
		t.Fatalf("config not prepended correctly:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if !strings.HasPrefix(got, "Include ~/.postern/ssh.conf\n") {
		t.Fatalf("Include is not the first line:\n%s", got)
	}
	if !strings.Contains(f.stdout.String(), "Added Include line") {
		t.Fatalf("stdout missing success line:\n%s", f.stdout.String())
	}
}

// TestSetupSSHIdempotent verifies a second run (Include already present) is a
// no-op that leaves the config byte-for-byte unchanged.
func TestSetupSSHIdempotent(t *testing.T) {
	f := newAddHostFixture(t)
	existing := "Include ~/.postern/ssh.conf\nHost solo\n  HostName 10.0.0.2\n"
	f.writeSSHConfig(t, existing)

	if err := execute(context.Background(), setupSSHRoot(f), "setup-ssh"); err != nil {
		t.Fatalf("Run(setup-ssh) error = %v", err)
	}

	data, _ := f.readSSHConfig(t)
	if string(data) != existing {
		t.Fatalf("idempotent run modified config:\nbefore:\n%s\nafter:\n%s", existing, data)
	}
	if !strings.Contains(f.stdout.String(), "already in ~/.ssh/config") {
		t.Fatalf("stdout missing already-configured line:\n%s", f.stdout.String())
	}
}

// TestSetupSSHCreatesDirAndFile verifies setup-ssh creates ~/.ssh (0700) and
// ~/.ssh/config (0600) when neither exists.
func TestSetupSSHCreatesDirAndFile(t *testing.T) {
	f := newAddHostFixture(t)
	if err := os.RemoveAll(f.sshDir); err != nil {
		t.Fatalf("RemoveAll(%q): %v", f.sshDir, err)
	}

	if err := execute(context.Background(), setupSSHRoot(f), "setup-ssh"); err != nil {
		t.Fatalf("Run(setup-ssh) error = %v", err)
	}

	dirInfo, err := os.Stat(f.sshDir)
	if err != nil {
		t.Fatalf("~/.ssh not created: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("~/.ssh mode = %o, want 0700", perm)
	}

	fileInfo, err := os.Stat(f.sshConfigPath)
	if err != nil {
		t.Fatalf("~/.ssh/config not created: %v", err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("~/.ssh/config mode = %o, want 0600", perm)
	}

	data, _ := f.readSSHConfig(t)
	if string(data) != "Include ~/.postern/ssh.conf\n" {
		t.Fatalf("config content = %q, want sole Include line", data)
	}
}

func TestSetupSSHCheckPresent(t *testing.T) {
	f := newAddHostFixture(t)
	f.writeSSHConfig(t, "Include ~/.postern/ssh.conf\n")

	if err := execute(context.Background(), setupSSHRoot(f), "setup-ssh", "--check"); err != nil {
		t.Fatalf("Run(setup-ssh --check) error = %v", err)
	}
	if !strings.Contains(f.stdout.String(), "is present") {
		t.Fatalf("stdout missing present message:\n%s", f.stdout.String())
	}
}

func TestSetupSSHCheckAbsent(t *testing.T) {
	f := newAddHostFixture(t)
	f.writeSSHConfig(t, "# empty\n")

	err := execute(context.Background(), setupSSHRoot(f), "setup-ssh", "--check")
	if err == nil {
		t.Fatal("Run(setup-ssh --check) returned nil error for absent Include")
	}
	out := f.stdout.String()
	if !strings.Contains(out, "is NOT present") {
		t.Fatalf("stdout missing absent message:\n%s", out)
	}
	if !strings.Contains(out, "setup-ssh") {
		t.Fatalf("stdout missing setup-ssh hint:\n%s", out)
	}
}
