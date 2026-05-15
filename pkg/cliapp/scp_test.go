package cliapp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/securetunnel"
	"github.com/atomicgravity/postern/internal/sshconf"
	"github.com/spf13/cobra"
)

// TestSCPArgvShape covers the canonical argv layout assembled for scp:
// "scp -i <key> -o CertificateFile=<cert> <args verbatim>". The wrapper
// prepends two flags; scp's own argument parser handles host:path detection
// and src/dst ordering.
func TestSCPArgvShape(t *testing.T) {
	cases := []struct {
		name string
		args []string
		tail []string
	}{
		{
			name: "download-from-device",
			args: []string{"scp", "device-1234", "engineer@192.168.1.42:/var/log/foo.log", "./foo.log"},
			tail: []string{"engineer@192.168.1.42:/var/log/foo.log", "./foo.log"},
		},
		{
			name: "upload-to-device",
			args: []string{"scp", "device-1234", "./payload.tar.gz", "engineer@192.168.1.42:/tmp/payload.tar.gz"},
			tail: []string{"./payload.tar.gz", "engineer@192.168.1.42:/tmp/payload.tar.gz"},
		},
		{
			name: "explicit-user",
			args: []string{"scp", "device-1234", "alice@192.168.1.42:/etc/config", "./config"},
			tail: []string{"alice@192.168.1.42:/etc/config", "./config"},
		},
		{
			name: "passthrough-scp-args",
			args: []string{"scp", "device-1234", "engineer@192.168.1.42:/foo", ".", "-p", "-r"},
			tail: []string{"engineer@192.168.1.42:/foo", ".", "-p", "-r"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, capture, recorder := newSCPTestRuntime(t)
			recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
				return broker.SSHCertIssueResponse{
					SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
				}
			}
			root := rootWithSCPForTest(rt)

			if err := execute(context.Background(), root, tc.args...); err != nil {
				t.Fatalf("Run(scp) error = %v", err)
			}

			certPath := filepath.Join(recorder.cacheDir, "default", "device-1234.cert")
			keyPath := filepath.Join(recorder.cacheDir, "default", "key")
			want := append([]string{
				"scp",
				"-i", keyPath,
				"-o", "CertificateFile=" + certPath,
				"-o", "IdentitiesOnly=yes",
				"-o", "PreferredAuthentications=publickey",
				"-o", "PasswordAuthentication=no",
				"-o", "KbdInteractiveAuthentication=no",
			}, tc.tail...)

			if got := capture.lastArgv(t); !reflect.DeepEqual(got, want) {
				t.Fatalf("argv = %v, want %v", got, want)
			}
		})
	}
}

// TestSCPCacheStateDecidesBrokerCall covers the mint-vs-reuse cache decision
// matrix: cache empty / cache hit comfortably valid / cache hit below the
// 5-minute safety margin / --refresh flag forcing re-mint. In every case scp
// exec must fire exactly once; broker calls depend on whether the cached cert
// is trustable for the upcoming transfer.
func TestSCPCacheStateDecidesBrokerCall(t *testing.T) {
	cases := []struct {
		name          string
		seedValidFor  time.Duration
		extraArgs     []string
		wantBrokerHit bool
	}{
		{name: "empty-cache", wantBrokerHit: true},
		{name: "hit-comfortable", seedValidFor: time.Hour, wantBrokerHit: false},
		{name: "hit-under-safety-margin", seedValidFor: 4 * time.Minute, wantBrokerHit: true},
		{name: "refresh-flag-forces-mint", seedValidFor: time.Hour, extraArgs: []string{"--refresh"}, wantBrokerHit: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, capture, recorder := newSCPTestRuntime(t)
			if tc.seedValidFor > 0 {
				seedCachedCert(t, recorder.cacheDir, recorder.ca, "device-1234", tc.seedValidFor)
			}
			if tc.wantBrokerHit {
				recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
					return broker.SSHCertIssueResponse{
						SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
					}
				}
			} else {
				recorder.response = func(broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
					t.Fatal("broker must not be called on a comfortable cache hit without --refresh")
					return broker.SSHCertIssueResponse{}
				}
			}
			root := rootWithSCPForTest(rt)

			args := append([]string{"scp"}, tc.extraArgs...)
			args = append(args, "device-1234", "engineer@192.168.1.42:/foo", "./foo")
			if err := execute(context.Background(), root, args...); err != nil {
				t.Fatalf("Run(scp) error = %v", err)
			}

			wantCalls := 0
			if tc.wantBrokerHit {
				wantCalls = 1
			}
			if recorder.calls != wantCalls {
				t.Fatalf("broker calls = %d, want %d", recorder.calls, wantCalls)
			}
			if len(capture.invocations) != 1 {
				t.Fatalf("execSCP invocations = %d, want 1", len(capture.invocations))
			}
		})
	}
}

// TestSCPTunnelHappyPath asserts the tunnel-mode flow composes broker
// MintSSHCert + broker OpenTunnel + securetunnel source-proxy start +
// scp subprocess. The scp argv carries -P <local-port> (UPPERCASE — scp's
// port flag, distinct from ssh's lowercase -p) + the HostName=127.0.0.1
// and NoHostAuthenticationForLocalhost=yes triad; the engineer-supplied
// user@host:path positionals are rewritten so the host segment becomes
// the device-id (so ~/.ssh/config Host <device-id> blocks apply); and the
// proxy is Closed + Waited on scp exit so no goroutines outlive the
// engineer's transfer.
func TestSCPTunnelHappyPath(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	tunnelCalls := newTunnelCallRecorder()
	rt.tunnelOpener = tunnelCalls.opener("source-token-xyz", "tunnel-abc", "us-east-1", 480)
	proxy := newFakeSourceProxy(42425)
	rt.sourceProxyStarter = proxy.starter()
	root := rootWithSCPForTest(rt)

	if err := execute(context.Background(), root, "scp", "--tunnel", "device-1234", "engineer@192.168.1.42:/var/log/foo.log", "./foo.log"); err != nil {
		t.Fatalf("Run(scp --tunnel) error = %v", err)
	}

	if len(capture.invocations) != 1 {
		t.Fatalf("execSCP invocations = %d, want 1", len(capture.invocations))
	}
	argv := capture.lastArgv(t)
	wantFlags := []string{
		"-P", "42425",
		"-o", "HostName=127.0.0.1",
		"-o", "NoHostAuthenticationForLocalhost=yes",
	}
	for _, flag := range wantFlags {
		if !contains(argv, flag) {
			t.Fatalf("argv missing %q: %v", flag, argv)
		}
	}
	// The remote positional's host segment is rewritten to the device-id
	// while the user portion and path survive. The local destination is
	// left alone.
	if !contains(argv, "engineer@device-1234:/var/log/foo.log") {
		t.Fatalf("argv missing rewritten remote spec engineer@device-1234:/var/log/foo.log: %v", argv)
	}
	if !contains(argv, "./foo.log") {
		t.Fatalf("argv missing local destination ./foo.log: %v", argv)
	}
	if proxy.closeCount() != 1 {
		t.Fatalf("proxy.Close calls = %d, want 1 (proxy must be torn down after scp exits)", proxy.closeCount())
	}
	if proxy.waitCount() != 1 {
		t.Fatalf("proxy.Wait calls = %d, want 1 (proxy goroutines must be joined)", proxy.waitCount())
	}
	if got := tunnelCalls.lastDeviceID(); got != "device-1234" {
		t.Fatalf("tunnelOpener device id = %q, want %q", got, "device-1234")
	}
	if got := tunnelCalls.lastMaxLifetime(); got != 0 {
		t.Fatalf("tunnelOpener max-lifetime = %d, want 0 (no flag → broker default)", got)
	}
}

// TestSCPTunnelRewritesBothRemoteEnds covers the symmetric-rewrite case:
// when both source AND dest are `user@host:path` (a cross-device or
// same-device remote-to-remote copy via the engineer's machine), both
// positionals get their host segments rewritten to the device-id. The
// engineer's chosen user portion on each leg is preserved independently.
func TestSCPTunnelRewritesBothRemoteEnds(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	tunnelCalls := newTunnelCallRecorder()
	rt.tunnelOpener = tunnelCalls.opener("source-token", "tunnel-id", "us-east-1", 480)
	proxy := newFakeSourceProxy(42426)
	rt.sourceProxyStarter = proxy.starter()
	root := rootWithSCPForTest(rt)

	if err := execute(context.Background(), root, "scp", "--tunnel", "device-1234", "alice@192.168.1.42:/etc/a", "bob@10.0.0.5:/tmp/b"); err != nil {
		t.Fatalf("Run(scp --tunnel) error = %v", err)
	}

	argv := capture.lastArgv(t)
	if !contains(argv, "alice@device-1234:/etc/a") {
		t.Fatalf("argv missing rewritten alice@device-1234:/etc/a: %v", argv)
	}
	if !contains(argv, "bob@device-1234:/tmp/b") {
		t.Fatalf("argv missing rewritten bob@device-1234:/tmp/b: %v", argv)
	}
}

// TestSCPTunnelLocalPathsLeftAlone covers the local-file-spec parsing:
// positionals without a host:path shape (relative or absolute file paths
// on the engineer's machine) pass through verbatim. The detector must
// not treat `./foo.log` or `/var/log/x` as remote even when they contain
// slashes — only `host:` (no leading slash before the colon) is remote.
func TestSCPTunnelLocalPathsLeftAlone(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	tunnelCalls := newTunnelCallRecorder()
	rt.tunnelOpener = tunnelCalls.opener("source-token", "tunnel-id", "us-east-1", 480)
	proxy := newFakeSourceProxy(42427)
	rt.sourceProxyStarter = proxy.starter()
	root := rootWithSCPForTest(rt)

	if err := execute(context.Background(), root, "scp", "--tunnel", "device-1234", "/var/log/local.log", "engineer@192.168.1.42:/tmp/local.log"); err != nil {
		t.Fatalf("Run(scp --tunnel) error = %v", err)
	}

	argv := capture.lastArgv(t)
	if !contains(argv, "/var/log/local.log") {
		t.Fatalf("local source path rewritten or missing: %v", argv)
	}
	if !contains(argv, "engineer@device-1234:/tmp/local.log") {
		t.Fatalf("remote dest not rewritten: %v", argv)
	}
}

// TestSCPTunnelAppendsDeviceIDWhenNoRemotePositional covers the defensive
// shape: if neither positional names a remote (which would normally fail
// at scp invocation anyway), the device-id is appended so scp's argv has
// a host argument and doesn't surface an opaque "usage" diagnostic from
// scp itself. The two positionals minimum is still enforced earlier via
// ErrSCPMissingPaths.
func TestSCPTunnelAppendsDeviceIDWhenNoRemotePositional(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	tunnelCalls := newTunnelCallRecorder()
	rt.tunnelOpener = tunnelCalls.opener("source-token", "tunnel-id", "us-east-1", 480)
	proxy := newFakeSourceProxy(33334)
	rt.sourceProxyStarter = proxy.starter()
	root := rootWithSCPForTest(rt)

	// Both positionals look local; the wrapper appends device-id as a
	// fresh argv element so scp has a host to talk to.
	if err := execute(context.Background(), root, "scp", "--tunnel", "device-1234", "./src", "./dst"); err != nil {
		t.Fatalf("Run(scp --tunnel) error = %v", err)
	}

	argv := capture.lastArgv(t)
	if got := argv[len(argv)-1]; got != "device-1234" {
		t.Fatalf("argv tail = %q, want %q", got, "device-1234")
	}
}

// TestSCPTunnelMaxLifetimeFlagFlowsToBroker covers the --max-lifetime
// plumb: the CLI duration converts to minutes and lands in the broker
// call site. Mirrors the ssh subcommand's table to assert scp's flag
// shape (DurationVar with the same name, zero-default, 12h cap, negative
// rejection, sub-minute round-up) matches ssh's verbatim.
func TestSCPTunnelMaxLifetimeFlagFlowsToBroker(t *testing.T) {
	cases := []struct {
		name         string
		flagValue    string
		wantMinutes  int32
		wantCLIError bool
	}{
		{name: "two-hours", flagValue: "2h", wantMinutes: 120},
		{name: "ninety-minutes", flagValue: "90m", wantMinutes: 90},
		{name: "thirty-seconds-rounds-to-one-minute", flagValue: "30s", wantMinutes: 1},
		{name: "zero-uses-broker-default", flagValue: "0s", wantMinutes: 0},
		{name: "exactly-twelve-hours-accepted", flagValue: "12h", wantMinutes: 720},
		{name: "above-twelve-hours-rejected", flagValue: "13h", wantCLIError: true},
		{name: "negative-rejected", flagValue: "-30m", wantCLIError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, _, recorder := newSCPTestRuntime(t)
			recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
				return broker.SSHCertIssueResponse{
					SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
				}
			}
			tunnelCalls := newTunnelCallRecorder()
			rt.tunnelOpener = tunnelCalls.opener("source-token", "tunnel-id", "us-east-1", 480)
			proxy := newFakeSourceProxy(40002)
			rt.sourceProxyStarter = proxy.starter()
			root := rootWithSCPForTest(rt)

			err := execute(context.Background(), root, "scp", "--tunnel", "--max-lifetime", tc.flagValue, "device-1234", "engineer@x:/foo", "./foo")

			if tc.wantCLIError {
				if err == nil {
					t.Fatalf("expected CLI-side rejection, got nil error")
				}
				if tunnelCalls.calls() != 0 {
					t.Fatalf("tunnelOpener called %d times, want 0 on CLI rejection", tunnelCalls.calls())
				}
				if proxy.startCount() != 0 {
					t.Fatalf("sourceProxyStarter called %d times, want 0 on CLI rejection", proxy.startCount())
				}
				return
			}
			if err != nil {
				t.Fatalf("Run(scp --tunnel) error = %v", err)
			}
			if got := tunnelCalls.lastMaxLifetime(); got != tc.wantMinutes {
				t.Fatalf("tunnelOpener max-lifetime = %d, want %d", got, tc.wantMinutes)
			}
		})
	}
}

// TestSCPTunnelSurfacesBrokerErrors covers the failure-mapping path: a
// broker /ssh/tunnel error (501 tunneling-disabled, 429 limit-exceeded,
// or any other status) flows out of the CLI verbatim so engineers see
// the structured broker reason. The source proxy must not be started
// on a broker error, and the scp subprocess must not run.
func TestSCPTunnelSurfacesBrokerErrors(t *testing.T) {
	cases := []struct {
		name       string
		brokerErr  error
		wantInText string
	}{
		{name: "tunneling-disabled-501", brokerErr: errors.New("open tunnel: status 501 Not Implemented: tunneling backend is not configured"), wantInText: "tunneling backend is not configured"},
		{name: "limit-exceeded-429", brokerErr: errors.New("open tunnel: status 429 Too Many Requests: tunnel_limit_exceeded"), wantInText: "tunnel_limit_exceeded"},
		{name: "policy-denied-403", brokerErr: errors.New("open tunnel: status 403 Forbidden: policy denied OpenTunnel"), wantInText: "policy denied"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, capture, recorder := newSCPTestRuntime(t)
			recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
				return broker.SSHCertIssueResponse{
					SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
				}
			}
			rt.tunnelOpener = func(context.Context, ResolvedProfile, string, string, int32) (broker.TunnelOpenResponse, error) {
				return broker.TunnelOpenResponse{}, tc.brokerErr
			}
			proxy := newFakeSourceProxy(40000)
			rt.sourceProxyStarter = proxy.starter()
			root := rootWithSCPForTest(rt)

			err := execute(context.Background(), root, "scp", "--tunnel", "device-1234", "engineer@x:/foo", "./foo")
			if err == nil {
				t.Fatalf("expected broker error, got nil")
			}
			if !errors.Is(err, tc.brokerErr) {
				t.Fatalf("Run(scp --tunnel) error = %v, want chain through %v", err, tc.brokerErr)
			}
			if !strings.Contains(err.Error(), tc.wantInText) {
				t.Fatalf("error %q missing expected substring %q", err.Error(), tc.wantInText)
			}
			if proxy.startCount() != 0 {
				t.Fatalf("sourceProxyStarter called %d times, want 0 (broker error must short-circuit)", proxy.startCount())
			}
			if len(capture.invocations) != 0 {
				t.Fatalf("execSCP invocations = %d, want 0", len(capture.invocations))
			}
		})
	}
}

// TestSCPTunnelSourceProxyStartFailure covers the path where /ssh/tunnel
// succeeds but the source proxy fails to start. The CLI must surface
// the proxy error and skip the scp exec.
func TestSCPTunnelSourceProxyStartFailure(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	rt.tunnelOpener = func(context.Context, ResolvedProfile, string, string, int32) (broker.TunnelOpenResponse, error) {
		return broker.TunnelOpenResponse{
			TunnelID:           "tunnel-id",
			SourceAccessToken:  "bad-token",
			Region:             "us-east-1",
			MaxLifetimeMinutes: 480,
		}, nil
	}
	startErr := errors.New("websocket: dial: 403 forbidden")
	rt.sourceProxyStarter = func(context.Context, securetunnel.SourceProxyOptions) (sourceProxy, error) {
		return nil, startErr
	}
	root := rootWithSCPForTest(rt)

	err := execute(context.Background(), root, "scp", "--tunnel", "device-1234", "engineer@x:/foo", "./foo")
	if !errors.Is(err, startErr) {
		t.Fatalf("Run(scp --tunnel) error = %v, want chain through %v", err, startErr)
	}
	if len(capture.invocations) != 0 {
		t.Fatalf("execSCP invocations = %d, want 0", len(capture.invocations))
	}
}

// TestSCPTunnelPreservesExitCode covers the exit-code propagation
// invariant: when scp exits non-zero (network failure, auth rejection
// at the device, etc.) the cliapp surfaces the *exec.ExitError so the
// engineer's shell sees the same exit code scp would have produced in
// direct-LAN mode. Proxy teardown still runs.
func TestSCPTunnelPreservesExitCode(t *testing.T) {
	rt, _, recorder := newSCPTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	rt.tunnelOpener = func(context.Context, ResolvedProfile, string, string, int32) (broker.TunnelOpenResponse, error) {
		return broker.TunnelOpenResponse{
			TunnelID:           "tunnel-id",
			SourceAccessToken:  "token",
			Region:             "us-east-1",
			MaxLifetimeMinutes: 480,
		}, nil
	}
	proxy := newFakeSourceProxy(45112)
	rt.sourceProxyStarter = proxy.starter()
	scpErr := errors.New("scp: exit status 1")
	rt.execSCP = func(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
		return scpErr
	}
	root := rootWithSCPForTest(rt)

	err := execute(context.Background(), root, "scp", "--tunnel", "device-1234", "engineer@x:/foo", "./foo")
	if !errors.Is(err, scpErr) {
		t.Fatalf("Run(scp --tunnel) error = %v, want chain through %v", err, scpErr)
	}
	if proxy.closeCount() != 1 || proxy.waitCount() != 1 {
		t.Fatalf("teardown skipped on scp failure: close=%d wait=%d", proxy.closeCount(), proxy.waitCount())
	}
}

// TestSCPTunnelVerboseRedactsSourceAccessToken covers invariant T: the
// source access token never appears in CLI verbose output, even though
// the engineer asked for diagnostics. Mirrors the ssh-side invariant; the
// scp path shares the tunnelDial helper so the diagnostic-emission
// surface is the same — but the test is duplicated rather than skipped
// because a regression that only affects scp's branch (e.g. an
// scp-flavored diagnostic added later that interpolates the proxy
// options) wouldn't be caught by the ssh-side test alone.
func TestSCPTunnelVerboseRedactsSourceAccessToken(t *testing.T) {
	rt, _, recorder := newSCPTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	const secretToken = "SECRET-AWS-SOURCE-TOKEN-DO-NOT-LOG"
	rt.tunnelOpener = func(context.Context, ResolvedProfile, string, string, int32) (broker.TunnelOpenResponse, error) {
		return broker.TunnelOpenResponse{
			TunnelID:           "tunnel-abc",
			SourceAccessToken:  secretToken,
			Region:             "us-east-1",
			MaxLifetimeMinutes: 480,
		}, nil
	}
	proxy := newFakeSourceProxy(40003)
	rt.sourceProxyStarter = proxy.starter()
	root := rootWithSCPForTest(rt)

	var stderr bytes.Buffer
	rootCmd := root
	rootCmd.SetErr(&stderr)
	if err := execute(context.Background(), rootCmd, "scp", "--tunnel", "-v", "device-1234", "engineer@x:/foo", "./foo"); err != nil {
		t.Fatalf("Run(scp --tunnel -v) error = %v", err)
	}

	if strings.Contains(stderr.String(), secretToken) {
		t.Fatalf("source access token leaked into verbose stderr:\n%s", stderr.String())
	}
	// The verbose output SHOULD still surface the tunnel id (engineer-
	// actionable diagnostic).
	if !strings.Contains(stderr.String(), "tunnel-abc") {
		t.Fatalf("verbose stderr missing tunnel id diagnostic:\n%s", stderr.String())
	}
}

// TestSCPMissingPaths covers the early-exit when scp doesn't have enough
// positionals after the device-id to attempt a src->dst transfer. scp itself
// would surface "usage" without naming the postern wrapping.
func TestSCPMissingPaths(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "no-positionals", args: []string{"scp", "device-1234"}},
		{name: "only-one-arg-after-device", args: []string{"scp", "device-1234", "./foo"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, capture, recorder := newSCPTestRuntime(t)
			recorder.response = func(broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
				t.Fatal("broker must not be called when paths are missing")
				return broker.SSHCertIssueResponse{}
			}
			root := rootWithSCPForTest(rt)

			err := execute(context.Background(), root, tc.args...)
			if !errors.Is(err, ErrSCPMissingPaths) {
				t.Fatalf("Run(scp %v) error = %v, want ErrSCPMissingPaths", tc.args, err)
			}
			if len(capture.invocations) != 0 {
				t.Fatalf("execSCP invocations = %d, want 0", len(capture.invocations))
			}
		})
	}
}

func TestSCPAuthFailureNamesLogin(t *testing.T) {
	tokenErr := errors.New("no token cached")
	rt, capture, recorder := newSCPTestRuntime(t)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "", tokenErr
	}
	recorder.response = func(broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		t.Fatal("broker must not be called when access-token retrieval fails")
		return broker.SSHCertIssueResponse{}
	}
	root := rootWithSCPForTest(rt)

	err := execute(context.Background(), root, "scp", "device-1234", "192.168.1.42:/foo", "./foo")
	if !errors.Is(err, ErrMintNoAuth) {
		t.Fatalf("Run(scp) error = %v, want ErrMintNoAuth", err)
	}
	if !errors.Is(err, tokenErr) {
		t.Fatalf("Run(scp) error = %v, want underlying token error preserved", err)
	}
	if !strings.Contains(err.Error(), `"postern" --profile "default" login`) {
		t.Fatalf("Run(scp) error = %v, want login hint", err)
	}
	if len(capture.invocations) != 0 {
		t.Fatalf("execSCP invocations = %d, want 0", len(capture.invocations))
	}
}

func TestSCPSurfacesBrokerErrors(t *testing.T) {
	brokerErr := errors.New("policy denied: device not in fleet")
	rt, capture, recorder := newSCPTestRuntime(t)
	rt.sshCertRequester = func(context.Context, ResolvedProfile, string, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		recorder.calls++
		return broker.SSHCertIssueResponse{}, brokerErr
	}
	root := rootWithSCPForTest(rt)

	err := execute(context.Background(), root, "scp", "device-1234", "192.168.1.42:/foo", "./foo")
	if !errors.Is(err, brokerErr) {
		t.Fatalf("Run(scp) error = %v, want broker error", err)
	}
	if len(capture.invocations) != 0 {
		t.Fatalf("execSCP invocations = %d, want 0", len(capture.invocations))
	}
}

// argvHasUserOption reports whether argv carries `-o User=<want>` (the
// split form scp's wrapper emits). Returns true on the first match.
func argvHasUserOption(argv []string, want string) bool {
	for i := 0; i < len(argv); i++ {
		if argv[i] == "-o" && i+1 < len(argv) && argv[i+1] == "User="+want {
			return true
		}
	}
	return false
}

// argvHasAnyUserOption reports whether argv carries any `-o User=...`
// pair. Used to assert that the wrapper did NOT inject a user override
// when the engineer's passthrough already pinned one (or when only the
// bare built-in default applies).
func argvHasAnyUserOption(argv []string) bool {
	for i := 0; i < len(argv); i++ {
		if argv[i] == "-o" && i+1 < len(argv) && strings.HasPrefix(argv[i+1], "User=") {
			return true
		}
	}
	return false
}

// TestSCPUserFlagAddsUserOption covers the new --user flag: it injects
// `-o User=<user>` into the scp argv. scp has no `-l login` (its `-l`
// is bandwidth-limit), so the override flows through the -o User=
// option which scp inherits from ssh_config syntax.
func TestSCPUserFlagAddsUserOption(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	root := rootWithSCPForTest(rt)

	if err := execute(context.Background(), root, "scp", "--user", "root", "device-1234", "./foo.txt", "device-1234:/tmp/foo"); err != nil {
		t.Fatalf("Run(scp --user) error = %v", err)
	}

	if got := capture.lastArgv(t); !argvHasUserOption(got, "root") {
		t.Fatalf("argv missing -o User=root: %v", got)
	}
}

// TestSCPUserResolutionSkippedWhenPassthroughHasUser locks the
// no-conflict rule: if the engineer's positional already carries
// user@host:path (or they pass -o User=...), postern does NOT also
// inject its own -o User=. scp's `-l 1000` (bandwidth) must NOT be
// treated as user info — skipDashL=true on the scp side handles that.
func TestSCPUserResolutionSkippedWhenPassthroughHasUser(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "user-at-host-path", args: []string{"scp", "device-1234", "./foo.txt", "alice@device-1234:/tmp/foo"}},
		{name: "dash-o-user", args: []string{"scp", "device-1234", "-o", "User=alice", "./foo.txt", "device-1234:/tmp/foo"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, capture, recorder := newSCPTestRuntime(t)
			rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
				return ResolvedProfile{
					Name:    "default",
					Profile: Profile{Broker: "https://broker.example.com", DefaultSSHUser: "opsteam"},
				}, nil
			}
			recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
				return broker.SSHCertIssueResponse{
					SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
				}
			}
			root := rootWithSCPForTest(rt)

			if err := execute(context.Background(), root, tc.args...); err != nil {
				t.Fatalf("Run(scp) error = %v", err)
			}

			argv := capture.lastArgv(t)
			if argvHasUserOption(argv, "opsteam") {
				t.Fatalf("postern injected -o User=opsteam despite passthrough user: %v", argv)
			}
		})
	}
}

// TestSCPBandwidthLimitNotMistakenForUser pins the skipDashL=true
// branch: scp's `-l 1000` is bandwidth-limit. The wrapper must NOT
// treat it as user info; resolveSCPCommandUser still flows the profile
// default through to -o User=.
func TestSCPBandwidthLimitNotMistakenForUser(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{
			Name:    "default",
			Profile: Profile{Broker: "https://broker.example.com", DefaultSSHUser: "opsteam"},
		}, nil
	}
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	root := rootWithSCPForTest(rt)

	if err := execute(context.Background(), root, "scp", "device-1234", "-l", "1000", "./foo.txt", "device-1234:/tmp/foo"); err != nil {
		t.Fatalf("Run(scp) error = %v", err)
	}

	if got := capture.lastArgv(t); !argvHasUserOption(got, "opsteam") {
		t.Fatalf("argv missing -o User=opsteam (bandwidth -l 1000 must not suppress profile default): %v", got)
	}
}

// TestSCPPersistentStanzaUserEmitsUserOption covers the integration of
// resolveUser into the scp path: a persistent <device> stanza's User
// directive flows through to `-o User=<stanza-user>`, overriding the
// profile default.
func TestSCPPersistentStanzaUserEmitsUserOption(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{
			Name:    "default",
			Profile: Profile{Broker: "https://broker.example.com", DefaultSSHUser: "opsteam"},
		}, nil
	}
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}

	writer, err := rt.openSSHConfWriter()
	if err != nil {
		t.Fatalf("openSSHConfWriter() error = %v", err)
	}
	if err := writer.Upsert(sshconf.Stanza{
		Device:          "device-1234",
		User:            "fleet-admin",
		IdentityFile:    "/seed/key",
		CertificateFile: "/seed/device-1234.cert",
	}); err != nil {
		t.Fatalf("seed Upsert() error = %v", err)
	}
	root := rootWithSCPForTest(rt)

	if err := execute(context.Background(), root, "scp", "device-1234", "./foo.txt", "device-1234:/tmp/foo"); err != nil {
		t.Fatalf("Run(scp) error = %v", err)
	}

	argv := capture.lastArgv(t)
	if !argvHasUserOption(argv, "fleet-admin") {
		t.Fatalf("argv missing -o User=fleet-admin (persistent stanza User should win over profile default): %v", argv)
	}
	if argvHasUserOption(argv, "opsteam") {
		t.Fatalf("argv carries profile default despite persistent stanza: %v", argv)
	}
}

// TestSCPBuiltInDefaultDoesNotEmitUserOption pins the implicit-fallback
// rule: when nothing is configured anywhere the wrapper skips emitting
// -o User= so a `Host *` User directive in the engineer's
// ~/.ssh/config keeps applying. The explicit bool from resolveUser
// (not a value-match sentinel) drives the choice.
func TestSCPBuiltInDefaultDoesNotEmitUserOption(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	root := rootWithSCPForTest(rt)

	if err := execute(context.Background(), root, "scp", "device-1234", "./foo.txt", "device-1234:/tmp/foo"); err != nil {
		t.Fatalf("Run(scp) error = %v", err)
	}

	if got := capture.lastArgv(t); argvHasAnyUserOption(got) {
		t.Fatalf("argv unexpectedly carries -o User= despite no configured user: %v", got)
	}
}

// TestSCPExplicitProfileEngineerEmitsUserOption pins the contrapositive
// of the implicit-fallback rule: when the engineer explicitly chose
// "engineer" as their profile default_ssh_user, the wrapper DOES emit
// -o User=engineer. "engineer" is a legitimate fleet username, not a
// sentinel; the explicit signal flows through.
func TestSCPExplicitProfileEngineerEmitsUserOption(t *testing.T) {
	rt, capture, recorder := newSCPTestRuntime(t)
	rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
		return ResolvedProfile{
			Name:    "default",
			Profile: Profile{Broker: "https://broker.example.com", DefaultSSHUser: DefaultSSHUser},
		}, nil
	}
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	root := rootWithSCPForTest(rt)

	if err := execute(context.Background(), root, "scp", "device-1234", "./foo.txt", "device-1234:/tmp/foo"); err != nil {
		t.Fatalf("Run(scp) error = %v", err)
	}

	if got := capture.lastArgv(t); !argvHasUserOption(got, DefaultSSHUser) {
		t.Fatalf("argv missing -o User=%s (explicit profile default_ssh_user: %s must emit): %v", DefaultSSHUser, DefaultSSHUser, got)
	}
}

// scpExecCapture mirrors sshExecCapture for the scp seam; keeping them
// distinct types makes test failures point at the right subcommand.
type scpExecCapture struct {
	invocations [][]string
}

func (c *scpExecCapture) hook() execSCPFunc {
	return func(_ context.Context, argv []string, _ io.Reader, _, _ io.Writer) error {
		argvCopy := append([]string(nil), argv...)
		c.invocations = append(c.invocations, argvCopy)
		return nil
	}
}

func (c *scpExecCapture) lastArgv(t *testing.T) []string {
	t.Helper()
	if len(c.invocations) == 0 {
		t.Fatal("execSCP was never invoked")
	}
	return c.invocations[len(c.invocations)-1]
}

func newSCPTestRuntime(t *testing.T) (runtime, *scpExecCapture, *brokerRecorder) {
	rt, recorder := newSubcommandTestRuntime(t)
	capture := &scpExecCapture{}
	rt.execSCP = capture.hook()
	return rt, capture, recorder
}

func rootWithSCPForTest(rt runtime) *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	var discard bytes.Buffer
	root.SetOut(&discard)
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.AddCommand(scpCommand(rt))
	return root
}
