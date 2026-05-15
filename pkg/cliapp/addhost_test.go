package cliapp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/sshconf"
	"github.com/spf13/cobra"
)

// addHostFixture is a self-contained add-host test environment: a fake $HOME,
// a tmpdir-rooted ssh.conf writer wired into the runtime, and a pre-existing
// ~/.ssh directory the test can populate with whatever ssh-config content
// it wants. Tests that don't care about ~/.ssh/config can ignore it. Since
// add-host now mints by default (LD-112), the fixture also wires a stub
// broker that returns a valid cert; tests covering the mint-failure path
// override rt.sshCertRequester to inject an error.
type addHostFixture struct {
	home          string
	sshDir        string
	sshConfigPath string
	sshConfPath   string
	rt            runtime
	stdout        *bytes.Buffer
	ca            *mintTestCA
	brokerCalls   *int
}

func newAddHostFixture(t *testing.T) *addHostFixture {
	t.Helper()
	if goruntime.GOOS == "windows" {
		t.Skip("addhost tests use HOME-based shim; not exercised on Windows")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q): %v", sshDir, err)
	}
	sshConfPath := filepath.Join(home, ".postern", "ssh.conf")

	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{
			Name:    "default",
			Profile: Profile{Broker: "https://broker.example.com"},
		}, nil
	}
	rt.openCertStore = openTestStore(filepath.Join(home, ".postern", "cache"))
	rt.openSSHConfWriter = func() (*sshconf.Writer, error) {
		return sshconf.NewWriter(sshConfPath), nil
	}
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "access-token", nil
	}

	ca := newMintTestCA(t)
	calls := 0
	rt.sshCertRequester = func(_ context.Context, _ ResolvedProfile, _ string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		calls++
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), request.DeviceID, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}, nil
	}

	return &addHostFixture{
		home:          home,
		sshDir:        sshDir,
		sshConfigPath: filepath.Join(sshDir, "config"),
		sshConfPath:   sshConfPath,
		rt:            rt,
		stdout:        &bytes.Buffer{},
		ca:            ca,
		brokerCalls:   &calls,
	}
}

func (f *addHostFixture) writeSSHConfig(t *testing.T, content string) {
	t.Helper()
	if err := os.WriteFile(f.sshConfigPath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", f.sshConfigPath, err)
	}
}

func (f *addHostFixture) readSSHConfig(t *testing.T) ([]byte, bool) {
	t.Helper()
	data, err := os.ReadFile(f.sshConfigPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false
		}
		t.Fatalf("ReadFile(%q): %v", f.sshConfigPath, err)
	}
	return data, true
}

func (f *addHostFixture) root() *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	root.SetOut(f.stdout)
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.AddCommand(addHostCommand(f.rt))
	root.AddCommand(removeHostCommand(f.rt))
	root.AddCommand(cacheCommand(f.rt))
	return root
}

func TestAddHostRegistersStanza(t *testing.T) {
	f := newAddHostFixture(t)

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42")
	if err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}

	data, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile(ssh.conf) error = %v", err)
	}
	content := string(data)
	for _, want := range []string{
		"BEGIN POSTERN-MANAGED: device-1234",
		"Host device-1234 192.168.1.42",
		"User engineer",
		"IdentityFile ",
		"CertificateFile ",
		"END POSTERN-MANAGED: device-1234",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("ssh.conf missing %q:\n%s", want, content)
		}
	}

	stdout := f.stdout.String()
	for _, want := range []string{
		"Registered device-1234",
		"192.168.1.42",
		"as user engineer",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout)
		}
	}
}

func TestAddHostDetectsIncludePresent(t *testing.T) {
	f := newAddHostFixture(t)
	f.writeSSHConfig(t, "# my notes\nInclude ~/.postern/ssh.conf\n")

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42")
	if err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}

	stdout := f.stdout.String()
	if !strings.Contains(stdout, "already in ~/.ssh/config") {
		t.Fatalf("stdout missing already-present message:\n%s", stdout)
	}
}

func TestAddHostDetectsIncludeAbsent(t *testing.T) {
	f := newAddHostFixture(t)
	f.writeSSHConfig(t, "# nothing to see here\n")

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42")
	if err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}

	stdout := f.stdout.String()
	if !strings.Contains(stdout, "was NOT found") {
		t.Fatalf("stdout missing absent-message:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Include ~/.postern/ssh.conf") {
		t.Fatalf("stdout missing literal Include line to add:\n%s", stdout)
	}
}

func TestAddHostHandlesMissingSSHConfig(t *testing.T) {
	f := newAddHostFixture(t)
	// No ~/.ssh/config at all.

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42")
	if err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}

	stdout := f.stdout.String()
	if !strings.Contains(stdout, "was NOT found") {
		t.Fatalf("stdout missing absent-message when config is missing:\n%s", stdout)
	}
	if _, exists := f.readSSHConfig(t); exists {
		t.Fatal("add-host created ~/.ssh/config; it must never write that file")
	}
}

// TestAddHostNeverModifiesUserSSHConfig is a regression guard for the
// "Postern never writes ~/.ssh/config" contract: regardless of whether the
// Include line is present, add-host must leave the engineer's ssh config
// byte-for-byte unchanged.
func TestAddHostNeverModifiesUserSSHConfig(t *testing.T) {
	cases := []struct {
		name         string
		preExisting  string
		preconfigure func(*addHostFixture, *testing.T)
	}{
		{
			name:        "include-present",
			preExisting: "# header\nInclude ~/.postern/ssh.conf\nHost other\n  HostName 10.0.0.1\n",
		},
		{
			name:        "include-absent",
			preExisting: "# header\nHost solo\n  HostName 10.0.0.2\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddHostFixture(t)
			f.writeSSHConfig(t, tc.preExisting)

			err := execute(context.Background(), f.root(),
				"add-host", "device-1234", "--ip", "192.168.1.42")
			if err != nil {
				t.Fatalf("Run(add-host) error = %v", err)
			}

			got, _ := f.readSSHConfig(t)
			if string(got) != tc.preExisting {
				t.Fatalf("~/.ssh/config modified by add-host:\nbefore:\n%s\nafter:\n%s",
					tc.preExisting, got)
			}
		})
	}
}

func TestAddHostUserFlagOverride(t *testing.T) {
	f := newAddHostFixture(t)

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42", "--user", "ops")
	if err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}

	data, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "User ops") {
		t.Fatalf("stanza missing override user:\n%s", content)
	}
	if strings.Contains(content, "User engineer") {
		t.Fatalf("stanza retained default user despite override:\n%s", content)
	}
}

// TestAddHostInheritsExistingStanzaUser covers the new four-tier
// precedence's persistent-stanza tier: rerunning `add-host` on a
// device that already has a stanza inherits the existing User
// directive when no --user is passed, overriding the profile default.
func TestAddHostInheritsExistingStanzaUser(t *testing.T) {
	f := newAddHostFixture(t)
	f.rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{
			Name: "default",
			Profile: Profile{
				Broker:         "https://broker.example.com",
				DefaultSSHUser: "opsteam",
			},
		}, nil
	}

	seed := sshconf.NewWriter(f.sshConfPath)
	if err := seed.Upsert(sshconf.Stanza{
		Device:          "device-1234",
		User:            "fleet-admin",
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/device-1234.cert",
	}); err != nil {
		t.Fatalf("seed Upsert() error = %v", err)
	}

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42")
	if err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}

	data, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "User fleet-admin") {
		t.Fatalf("stanza did not inherit existing User over profile default:\n%s", data)
	}
	if strings.Contains(string(data), "User opsteam") {
		t.Fatalf("stanza picked profile default despite existing stanza User:\n%s", data)
	}
}

func TestAddHostDefaultUserFromProfile(t *testing.T) {
	f := newAddHostFixture(t)
	f.rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{
			Name: "default",
			Profile: Profile{
				Broker:         "https://broker.example.com",
				DefaultSSHUser: "opsteam",
			},
		}, nil
	}

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42")
	if err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}

	data, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "User opsteam") {
		t.Fatalf("stanza missing profile default user:\n%s", data)
	}
}

func TestAddHostPortFlag(t *testing.T) {
	f := newAddHostFixture(t)

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42", "--port", "2222")
	if err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}

	data, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "Port 2222") {
		t.Fatalf("stanza missing Port directive:\n%s", data)
	}
}

func TestAddHostRejectsInvalidDeviceID(t *testing.T) {
	f := newAddHostFixture(t)
	cases := []struct {
		name      string
		device    string
		wantInErr string
	}{
		{"path-traversal", "../escape", "path separators"},
		{"forward-slash", "a/b", "path separators"},
		{"backslash", `a\b`, "path separators"},
		{"dotdot", "..", "'..' is not allowed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f.stdout.Reset()
			err := execute(context.Background(), f.root(),
				"add-host", tc.device, "--ip", "192.168.1.42")
			if err == nil {
				t.Fatalf("Run(add-host %q) returned nil error", tc.device)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("Run(add-host %q) error = %v, want substring %q",
					tc.device, err, tc.wantInErr)
			}
		})
	}
}

func TestAddHostCheckFlagPresent(t *testing.T) {
	f := newAddHostFixture(t)
	f.writeSSHConfig(t, "Include ~/.postern/ssh.conf\n")

	err := execute(context.Background(), f.root(), "add-host", "--check")
	if err != nil {
		t.Fatalf("Run(add-host --check) error = %v", err)
	}
	if !strings.Contains(f.stdout.String(), "is present") {
		t.Fatalf("stdout missing present message:\n%s", f.stdout.String())
	}
}

func TestAddHostCheckFlagAbsent(t *testing.T) {
	f := newAddHostFixture(t)
	f.writeSSHConfig(t, "# empty\n")

	err := execute(context.Background(), f.root(), "add-host", "--check")
	if err == nil {
		t.Fatal("Run(add-host --check) returned nil error for absent Include line")
	}
	if !strings.Contains(f.stdout.String(), "is NOT present") {
		t.Fatalf("stdout missing absent message:\n%s", f.stdout.String())
	}
}

// TestAddHostMintByDefault locks the LD-112 contract: a vanilla
// `add-host <device>` hits the broker, caches the cert, writes the
// ssh.conf stanza, and the summary mentions the cert TTL plus the
// vanilla `ssh <device>` connect line.
func TestAddHostMintByDefault(t *testing.T) {
	f := newAddHostFixture(t)
	f.writeSSHConfig(t, "Include ~/.postern/ssh.conf\n")

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42")
	if err != nil {
		t.Fatalf("Run(add-host) error = %v", err)
	}

	if got := *f.brokerCalls; got != 1 {
		t.Fatalf("broker calls = %d, want 1 (add-host must mint by default)", got)
	}

	certPath := filepath.Join(f.home, ".postern", "cache", "default", "device-1234.cert")
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("cert cache entry missing after add-host: %v", err)
	}

	out := f.stdout.String()
	for _, want := range []string{
		"Registered device-1234",
		"Cert minted, valid until",
		"remaining",
		"ssh device-1234",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q:\n%s", want, out)
		}
	}
}

// TestAddHostMintFailureAbortsWrite locks the load-bearing mint-then-write
// ordering: when the broker fails the mint, no ssh.conf stanza must
// land (LD-112). A half-state where the stanza references a missing
// cache entry is worse than no stanza at all.
func TestAddHostMintFailureAbortsWrite(t *testing.T) {
	f := newAddHostFixture(t)
	mintErr := errors.New("policy denied: device not in fleet")
	f.rt.sshCertRequester = func(context.Context, ResolvedProfile, string, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		return broker.SSHCertIssueResponse{}, mintErr
	}

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42")
	if !errors.Is(err, mintErr) {
		t.Fatalf("Run(add-host) error = %v, want broker error wrapped", err)
	}

	if _, err := os.Stat(f.sshConfPath); err == nil {
		// File exists. Confirm the stanza for this device is not in it.
		data, _ := os.ReadFile(f.sshConfPath)
		if strings.Contains(string(data), "BEGIN POSTERN-MANAGED: device-1234") {
			t.Fatalf("ssh.conf stanza landed despite mint failure:\n%s", data)
		}
	}
	// If the file doesn't exist at all that's also correct — no stanza
	// was written.
}

// TestAddHostNoMintFlag locks the offline-staging path: --no-mint
// skips the broker, writes the stanza, and the summary suggests
// `mint` as the explicit next step (no cert TTL line, since none
// was minted).
func TestAddHostNoMintFlag(t *testing.T) {
	f := newAddHostFixture(t)
	f.writeSSHConfig(t, "Include ~/.postern/ssh.conf\n")
	f.rt.sshCertRequester = func(context.Context, ResolvedProfile, string, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		t.Fatal("broker must not be called when --no-mint is set")
		return broker.SSHCertIssueResponse{}, nil
	}

	err := execute(context.Background(), f.root(),
		"add-host", "device-1234", "--ip", "192.168.1.42", "--no-mint")
	if err != nil {
		t.Fatalf("Run(add-host --no-mint) error = %v", err)
	}

	data, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile(ssh.conf) error = %v", err)
	}
	if !strings.Contains(string(data), "BEGIN POSTERN-MANAGED: device-1234") {
		t.Fatalf("ssh.conf stanza not written under --no-mint:\n%s", data)
	}

	out := f.stdout.String()
	if strings.Contains(out, "Cert minted") {
		t.Fatalf("stdout claims cert minted under --no-mint:\n%s", out)
	}
	if !strings.Contains(out, "mint device-1234") {
		t.Fatalf("stdout missing mint suggestion under --no-mint:\n%s", out)
	}
}
