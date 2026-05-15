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

// tunnelOpenFixture mirrors the addHostFixture / newSSHTestRuntime
// pattern: a self-contained environment for `postern tunnel <device>`
// tests with a tmpdir-rooted ssh.conf writer, fake broker, and fake
// source-proxy. Tests drive the lifecycle via the supplied context.
type tunnelOpenFixture struct {
	t           *testing.T
	sshConfPath string
	rt          runtime
	stdout      *bytes.Buffer
	stderr      *bytes.Buffer
	tunnelCalls *tunnelCallRecorder
	proxy       *fakeSourceProxy
}

func newTunnelOpenFixture(t *testing.T) *tunnelOpenFixture {
	t.Helper()
	if goruntime.GOOS == "windows" {
		t.Skip("tunnel-open tests rely on POSIX pid liveness for the reaper invariant")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	sshConfPath := filepath.Join(home, ".postern", "ssh.conf")
	cacheDir := filepath.Join(home, ".postern", "cache")

	ca := newMintTestCA(t)

	rt := newRuntimeForTest(Options{LookupEnv: emptyEnv})
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{
			Name:    "default",
			Profile: Profile{Broker: "https://broker.example.com"},
		}, nil
	}
	rt.openCertStore = openTestStore(cacheDir)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "access-token", nil
	}
	rt.sshCertRequester = func(_ context.Context, _ ResolvedProfile, _ string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), request.DeviceID, time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}, nil
	}
	rt.openSSHConfWriter = func() (*sshconf.Writer, error) {
		return sshconf.NewWriter(sshConfPath), nil
	}

	recorder := newTunnelCallRecorder()
	rt.tunnelOpener = recorder.opener("source-token-secret", "tunnel-id-abc", "us-east-1", 480)
	proxy := newFakeSourceProxy(40404)
	rt.sourceProxyStarter = proxy.starter()

	return &tunnelOpenFixture{
		t:           t,
		sshConfPath: sshConfPath,
		rt:          rt,
		stdout:      &bytes.Buffer{},
		stderr:      &bytes.Buffer{},
		tunnelCalls: recorder,
		proxy:       proxy,
	}
}

func (f *tunnelOpenFixture) root() *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	root.SetOut(f.stdout)
	root.SetErr(f.stderr)
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.AddCommand(tunnelCommand(f.rt))
	return root
}

// runWithControlledContext spawns the cobra command on a goroutine
// and returns the cancel func + a wait func. Tests call cancel()
// when they've verified the pre-cancel state (stanza written, proxy
// started); the wait func returns the command's error.
func (f *tunnelOpenFixture) runWithControlledContext(args ...string) (cancel func(), wait func() error) {
	ctx, cancelFn := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		root := f.root()
		root.SetArgs(args)
		done <- root.ExecuteContext(ctx)
	}()
	return cancelFn, func() error {
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			cancelFn()
			f.t.Fatalf("tunnel command did not return within 5s of cancel; deadlock suspected")
			return nil
		}
	}
}

// waitForUpsert polls the ssh.conf file until the stanza for device
// appears (or the deadline expires). Returns the file contents at
// the time it became visible.
func (f *tunnelOpenFixture) waitForUpsert(device string) string {
	f.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(f.sshConfPath)
		if err == nil && strings.Contains(string(data), "BEGIN POSTERN-MANAGED: "+device) {
			return string(data)
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatalf("ephemeral stanza for %s did not appear within 3s", device)
	return ""
}

// waitForStartCount polls until the source proxy's start counter
// reaches want (or times out). Tests use it when --port-only paths
// skip the ssh.conf write so the waitForUpsert handle isn't usable.
func (f *tunnelOpenFixture) waitForStartCount(want int) {
	f.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f.proxy.startCount() >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.t.Fatalf("source proxy start count = %d, want %d after 3s", f.proxy.startCount(), want)
}

// TestTunnelOpenHappyPath covers the load-bearing tunnel-open
// lifecycle: tunnelDial composes mint + broker.OpenTunnel + source
// proxy start; UpsertEphemeral writes the transient ssh.conf block at
// the suffixed `<device>.tunnel` Host name with the pid+opened
// sentinel + the loopback Port; signal/cancel triggers
// RemoveEphemeral; proxy is Closed+Waited.
func TestTunnelOpenHappyPath(t *testing.T) {
	f := newTunnelOpenFixture(t)

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234")

	// Wait for the suffixed stanza to land so we know the pre-cancel
	// state is fully established before we signal.
	content := f.waitForUpsert("device-1234.tunnel")
	for _, want := range []string{
		"BEGIN POSTERN-MANAGED: device-1234.tunnel",
		"# POSTERN-EPHEMERAL: pid=",
		"Host device-1234.tunnel",
		"HostName 127.0.0.1",
		"Port 40404",
		"END POSTERN-MANAGED: device-1234.tunnel",
	} {
		if !strings.Contains(content, want) {
			t.Fatalf("ssh.conf missing %q:\n%s", want, content)
		}
	}
	// And the un-suffixed name is NOT touched by the tunnel path.
	if strings.Contains(content, "BEGIN POSTERN-MANAGED: device-1234\n") {
		t.Fatalf("tunnel path wrote a block at the un-suffixed device name:\n%s", content)
	}

	cancel()
	if err := wait(); err != nil {
		t.Fatalf("tunnel command returned error = %v", err)
	}

	if f.proxy.closeCount() != 1 {
		t.Fatalf("proxy.Close calls = %d, want 1", f.proxy.closeCount())
	}
	if f.proxy.waitCount() != 1 {
		t.Fatalf("proxy.Wait calls = %d, want 1", f.proxy.waitCount())
	}
	if got := f.tunnelCalls.lastDeviceID(); got != "device-1234" {
		t.Fatalf("tunnelOpener device id = %q, want device-1234 (un-suffixed name still used for the broker call)", got)
	}

	// After cancel + clean shutdown, the ephemeral stanza must be
	// gone — RemoveEphemeral deletes it, leaving the file effectively
	// empty (header-only).
	data, _ := os.ReadFile(f.sshConfPath)
	if strings.Contains(string(data), "BEGIN POSTERN-MANAGED: device-1234.tunnel") {
		t.Fatalf("ephemeral stanza survived clean shutdown:\n%s", data)
	}
}

// TestTunnelOpenLeavesPersistentStanzaAlone covers the new no-restore
// contract: a pre-existing persistent stanza for the un-suffixed
// device name is untouched both during the tunnel's lifetime and
// after RemoveEphemeral on shutdown. Engineers can `ssh <device>`
// (direct LAN) and `ssh <device>.tunnel` (proxied) concurrently.
func TestTunnelOpenLeavesPersistentStanzaAlone(t *testing.T) {
	f := newTunnelOpenFixture(t)

	// Seed a persistent stanza first.
	seed := sshconf.NewWriter(f.sshConfPath)
	if err := seed.Upsert(sshconf.Stanza{
		Device:          "device-1234",
		Patterns:        []string{"192.168.1.42"},
		User:            "engineer",
		Port:            22,
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/device-1234.cert",
	}); err != nil {
		t.Fatalf("seed Upsert() error = %v", err)
	}
	originalRaw, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234")
	// Wait for the suffixed stanza to appear; the un-suffixed
	// stanza must still be present alongside it.
	mid := f.waitForUpsert("device-1234.tunnel")
	if !strings.Contains(mid, "BEGIN POSTERN-MANAGED: device-1234\n") {
		t.Fatalf("persistent stanza was disturbed while tunnel was open:\n%s", mid)
	}

	cancel()
	if err := wait(); err != nil {
		t.Fatalf("tunnel command returned error = %v", err)
	}

	gotRaw, err := os.ReadFile(f.sshConfPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(gotRaw) != string(originalRaw) {
		t.Fatalf("persistent stanza mutated by tunnel lifecycle:\nbefore:\n%s\nafter:\n%s", originalRaw, gotRaw)
	}
}

// TestTunnelOpenInheritsUserFromPersistentStanza covers the new
// user-inheritance precedence: with no --user flag, a persistent
// stanza's User directive is carried into the ephemeral stanza so
// `ssh <device>.tunnel` connects with the same login as `ssh <device>`
// would.
func TestTunnelOpenInheritsUserFromPersistentStanza(t *testing.T) {
	f := newTunnelOpenFixture(t)

	seed := sshconf.NewWriter(f.sshConfPath)
	if err := seed.Upsert(sshconf.Stanza{
		Device:          "device-1234",
		User:            "amir-operator",
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/device-1234.cert",
	}); err != nil {
		t.Fatalf("seed Upsert() error = %v", err)
	}

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234")
	content := f.waitForUpsert("device-1234.tunnel")

	// Find the ephemeral stanza's User line. The persistent stanza
	// also carries User, so substring-only matches would be
	// ambiguous; extract the suffixed block first.
	const beginEph = "# BEGIN POSTERN-MANAGED: device-1234.tunnel\n"
	const endEph = "# END POSTERN-MANAGED: device-1234.tunnel\n"
	beginIdx := strings.Index(content, beginEph)
	endIdx := strings.Index(content, endEph)
	if beginIdx < 0 || endIdx < 0 {
		cancel()
		_ = wait()
		t.Fatalf("could not locate ephemeral block:\n%s", content)
	}
	ephBlock := content[beginIdx : endIdx+len(endEph)]
	if !strings.Contains(ephBlock, "User amir-operator") {
		cancel()
		_ = wait()
		t.Fatalf("ephemeral stanza did not inherit persistent User:\n%s", ephBlock)
	}

	cancel()
	if err := wait(); err != nil {
		t.Fatalf("tunnel command returned error = %v", err)
	}
}

// TestTunnelOpenUserFlagBeatsPersistentInheritance pins the
// precedence: an explicit --user flag wins over the persistent
// stanza's User directive.
func TestTunnelOpenUserFlagBeatsPersistentInheritance(t *testing.T) {
	f := newTunnelOpenFixture(t)

	seed := sshconf.NewWriter(f.sshConfPath)
	if err := seed.Upsert(sshconf.Stanza{
		Device:          "device-1234",
		User:            "amir-operator",
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/device-1234.cert",
	}); err != nil {
		t.Fatalf("seed Upsert() error = %v", err)
	}

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234", "--user", "root")
	content := f.waitForUpsert("device-1234.tunnel")

	const beginEph = "# BEGIN POSTERN-MANAGED: device-1234.tunnel\n"
	const endEph = "# END POSTERN-MANAGED: device-1234.tunnel\n"
	beginIdx := strings.Index(content, beginEph)
	endIdx := strings.Index(content, endEph)
	if beginIdx < 0 || endIdx < 0 {
		cancel()
		_ = wait()
		t.Fatalf("could not locate ephemeral block:\n%s", content)
	}
	ephBlock := content[beginIdx : endIdx+len(endEph)]
	if !strings.Contains(ephBlock, "User root") {
		cancel()
		_ = wait()
		t.Fatalf("--user override did not win over persistent inheritance:\n%s", ephBlock)
	}
	if strings.Contains(ephBlock, "User amir-operator") {
		cancel()
		_ = wait()
		t.Fatalf("persistent User leaked into ephemeral stanza despite --user flag:\n%s", ephBlock)
	}

	cancel()
	if err := wait(); err != nil {
		t.Fatalf("tunnel command returned error = %v", err)
	}
}

// TestTunnelOpenFallsBackToProfileDefault covers the third leg of
// precedence: no --user flag and no persistent stanza falls through
// to the profile default (the runtime's resolveDefaultSSHUser).
func TestTunnelOpenFallsBackToProfileDefault(t *testing.T) {
	f := newTunnelOpenFixture(t)

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234")
	content := f.waitForUpsert("device-1234.tunnel")

	// The fixture's profile leaves DefaultSSHUser blank, so
	// resolveDefaultSSHUser returns the package-level
	// DefaultSSHUser constant.
	if !strings.Contains(content, "User "+DefaultSSHUser) {
		cancel()
		_ = wait()
		t.Fatalf("ephemeral stanza missing profile-default User %q:\n%s", DefaultSSHUser, content)
	}

	cancel()
	if err := wait(); err != nil {
		t.Fatalf("tunnel command returned error = %v", err)
	}
}

// TestTunnelOpenPortOnlySkipsSSHConf covers OQ-TN-F-2: --port-only
// prints the loopback port and holds open, but writes no ssh.conf
// stanza.
func TestTunnelOpenPortOnlySkipsSSHConf(t *testing.T) {
	f := newTunnelOpenFixture(t)

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234", "--port-only")
	f.waitForStartCount(1)

	cancel()
	if err := wait(); err != nil {
		t.Fatalf("tunnel command returned error = %v", err)
	}

	if _, err := os.Stat(f.sshConfPath); err == nil {
		data, _ := os.ReadFile(f.sshConfPath)
		if strings.Contains(string(data), "BEGIN POSTERN-MANAGED: device-1234") {
			t.Fatalf("--port-only wrote ssh.conf stanza:\n%s", data)
		}
	}

	out := f.stdout.String()
	if !strings.Contains(out, "Local port: 40404") {
		t.Fatalf("stdout missing port line:\n%s", out)
	}
}

// TestTunnelOpenRejectsConcurrentSameDevice covers OQ-TN-F-1: a
// second `postern tunnel <device>` against the same device while the
// first is still live errors out via ErrEphemeralConcurrent (the
// writer's same-device-pid-alive guard, keyed on the suffixed name).
func TestTunnelOpenRejectsConcurrentSameDevice(t *testing.T) {
	f := newTunnelOpenFixture(t)

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234")
	f.waitForUpsert("device-1234.tunnel")

	// Now run a second invocation against the same device with a
	// separate fixture sharing the same ssh.conf path. Its writer
	// will see the live first-invocation's pid (== os.Getpid()) on
	// the .tunnel-suffixed block and reject.
	secondRoot := f.root()
	secondRoot.SetArgs([]string{"tunnel", "device-1234"})
	err := secondRoot.ExecuteContext(context.Background())

	cancel()
	if waitErr := wait(); waitErr != nil {
		t.Fatalf("first tunnel command returned error = %v", waitErr)
	}

	if err == nil {
		t.Fatal("second tunnel invocation returned nil; want concurrent error")
	}
	var concurrent *sshconf.ErrEphemeralConcurrent
	if !errors.As(err, &concurrent) {
		t.Fatalf("second tunnel error = %v, want ErrEphemeralConcurrent", err)
	}
}

// TestTunnelOpenReaperFlag covers the --reap manual-escape-hatch
// path: running `postern tunnel --reap` cleans up stale ephemeral
// stanzas and exits without opening a tunnel.
func TestTunnelOpenReaperFlag(t *testing.T) {
	f := newTunnelOpenFixture(t)

	// Seed a stale ephemeral stanza by hand (dead pid) at the
	// suffixed name.
	seed := sshconf.NewWriter(f.sshConfPath)
	deadPid := os.Getpid() + 1_000_000
	if err := seed.UpsertEphemeral(sshconf.Stanza{
		Device:          "device-stale.tunnel",
		HostName:        "127.0.0.1",
		User:            "engineer",
		Port:            12345,
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/device-stale.cert",
	}, deadPid, time.Now().UTC()); err != nil {
		t.Fatalf("seed UpsertEphemeral() error = %v", err)
	}

	if err := execute(context.Background(), f.root(), "tunnel", "--reap"); err != nil {
		t.Fatalf("tunnel --reap error = %v", err)
	}

	if f.proxy.startCount() != 0 {
		t.Fatalf("source proxy started during --reap: count = %d", f.proxy.startCount())
	}

	data, _ := os.ReadFile(f.sshConfPath)
	if strings.Contains(string(data), "BEGIN POSTERN-MANAGED: device-stale.tunnel") {
		t.Fatalf("stale ephemeral stanza survived --reap:\n%s", data)
	}

	if !strings.Contains(f.stdout.String(), "device-stale.tunnel") {
		t.Fatalf("--reap stdout missing reaped device:\n%s", f.stdout.String())
	}
}

// TestTunnelOpenReapsStaleBeforeUpsert covers the load-bearing
// reaper-before-write ordering: a stale ephemeral stanza from a
// different device with a dead pid must be cleaned up before the new
// invocation writes its own stanza.
func TestTunnelOpenReapsStaleBeforeUpsert(t *testing.T) {
	f := newTunnelOpenFixture(t)

	seed := sshconf.NewWriter(f.sshConfPath)
	deadPid := os.Getpid() + 1_000_000
	if err := seed.UpsertEphemeral(sshconf.Stanza{
		Device:          "device-stale.tunnel",
		HostName:        "127.0.0.1",
		User:            "engineer",
		Port:            55555,
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/device-stale.cert",
	}, deadPid, time.Now().UTC()); err != nil {
		t.Fatalf("seed UpsertEphemeral() error = %v", err)
	}

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234")
	f.waitForUpsert("device-1234.tunnel")

	data, _ := os.ReadFile(f.sshConfPath)
	if strings.Contains(string(data), "BEGIN POSTERN-MANAGED: device-stale.tunnel") {
		t.Fatalf("stale ephemeral stanza survived past reaper:\n%s", data)
	}

	cancel()
	if err := wait(); err != nil {
		t.Fatalf("tunnel command returned error = %v", err)
	}
}

// TestTunnelOpenSourceTokenNotLogged is invariant T for the
// tunnel-open path: even at -v the source access token must not
// appear in any stderr / stdout output.
func TestTunnelOpenSourceTokenNotLogged(t *testing.T) {
	f := newTunnelOpenFixture(t)
	const secretToken = "SECRET-AWS-SOURCE-TOKEN-DO-NOT-LOG"
	f.rt.tunnelOpener = func(context.Context, ResolvedProfile, string, string, int32) (broker.TunnelOpenResponse, error) {
		return broker.TunnelOpenResponse{
			TunnelID:           "tunnel-abc",
			SourceAccessToken:  secretToken,
			Region:             "us-east-1",
			MaxLifetimeMinutes: 480,
		}, nil
	}

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234", "-v")
	f.waitForUpsert("device-1234.tunnel")
	cancel()
	if err := wait(); err != nil {
		t.Fatalf("tunnel command returned error = %v", err)
	}

	combined := f.stdout.String() + f.stderr.String()
	if strings.Contains(combined, secretToken) {
		t.Fatalf("source access token leaked into output:\n%s", combined)
	}
	// The tunnel id is engineer-actionable diagnostic and should appear
	// under -v.
	if !strings.Contains(f.stderr.String(), "tunnel-abc") {
		t.Fatalf("verbose stderr missing tunnel id (engineer-actionable):\n%s", f.stderr.String())
	}
}

// TestTunnelOpenUpsertFailureClosesProxy covers the failure-mapping
// path: when UpsertEphemeral fails (e.g. live concurrent block on the
// suffixed name), the source proxy must be torn down so no WebSocket
// goroutine outlives the failed invocation.
func TestTunnelOpenUpsertFailureClosesProxy(t *testing.T) {
	f := newTunnelOpenFixture(t)

	// Seed a live-pid ephemeral stanza at the suffixed name so
	// UpsertEphemeral inside runTunnelOpen rejects on concurrent.
	seed := sshconf.NewWriter(f.sshConfPath)
	if err := seed.UpsertEphemeral(sshconf.Stanza{
		Device:          "device-1234.tunnel",
		HostName:        "127.0.0.1",
		User:            "engineer",
		Port:            11111,
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/device-1234.cert",
	}, os.Getpid(), time.Now().UTC()); err != nil {
		t.Fatalf("seed UpsertEphemeral() error = %v", err)
	}

	err := execute(context.Background(), f.root(), "tunnel", "device-1234")
	if err == nil {
		t.Fatal("expected concurrent error, got nil")
	}
	if f.proxy.startCount() != 1 {
		t.Fatalf("source proxy start count = %d, want 1", f.proxy.startCount())
	}
	if f.proxy.closeCount() != 1 {
		t.Fatalf("source proxy close count = %d, want 1 (must tear down on upsert failure)", f.proxy.closeCount())
	}
	if f.proxy.waitCount() != 1 {
		t.Fatalf("source proxy wait count = %d, want 1", f.proxy.waitCount())
	}
}

// TestTunnelOpenUserFlag covers --user override (no persistent
// stanza in the way): the transient stanza carries the engineer-
// supplied user, not the profile default.
func TestTunnelOpenUserFlag(t *testing.T) {
	f := newTunnelOpenFixture(t)

	cancel, wait := f.runWithControlledContext("tunnel", "device-1234", "--user", "root")
	f.waitForUpsert("device-1234.tunnel")
	data, _ := os.ReadFile(f.sshConfPath)
	if !strings.Contains(string(data), "User root") {
		cancel()
		_ = wait()
		t.Fatalf("transient stanza missing --user override:\n%s", data)
	}
	cancel()
	if err := wait(); err != nil {
		t.Fatalf("tunnel command returned error = %v", err)
	}
}

// TestTunnelOpenMaxLifetimeRejected covers --max-lifetime validation
// at the CLI boundary: negative / above-12h values surface a clean
// error before the broker round-trip. Mirrors the ssh / scp tunnel-
// mode flow.
func TestTunnelOpenMaxLifetimeRejected(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  error
	}{
		{name: "negative", value: "-30m", want: ErrTunnelNegativeLifetime},
		{name: "above-ceiling", value: "13h", want: ErrTunnelLifetimeExceedsCeiling},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTunnelOpenFixture(t)
			err := execute(context.Background(), f.root(), "tunnel", "device-1234", "--max-lifetime", tc.value)
			if !errors.Is(err, tc.want) {
				t.Fatalf("tunnel --max-lifetime %s error = %v, want %v", tc.value, err, tc.want)
			}
			if f.proxy.startCount() != 0 {
				t.Fatalf("source proxy started after CLI rejection: count = %d", f.proxy.startCount())
			}
		})
	}
}

// TestTunnelOpenMissingDeviceID covers the boundary check: no device
// id with no --reap is an error before the runtime is touched.
func TestTunnelOpenMissingDeviceID(t *testing.T) {
	f := newTunnelOpenFixture(t)
	err := execute(context.Background(), f.root(), "tunnel")
	if err == nil {
		t.Fatal("tunnel without device-id returned nil error")
	}
	if !strings.Contains(err.Error(), "device id is required") {
		t.Fatalf("tunnel error = %v, want 'device id is required'", err)
	}
}
