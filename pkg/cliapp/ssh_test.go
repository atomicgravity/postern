package cliapp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/certcache"
	"github.com/atomicgravity/postern/internal/securetunnel"
	"github.com/atomicgravity/postern/internal/sshconf"
	"github.com/spf13/cobra"
)

// TestSSHCacheStateDecidesBrokerCall covers the mint-vs-reuse cache decision
// matrix: cache empty / cache hit comfortably valid / cache hit below the
// 5-minute safety margin / --refresh flag forcing re-mint. In every case ssh
// exec must fire exactly once; broker calls depend on whether the cached cert
// is trustable for the upcoming session.
func TestSSHCacheStateDecidesBrokerCall(t *testing.T) {
	cases := []struct {
		name          string
		seedValidFor  time.Duration // zero == leave cache empty
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
			rt, capture, recorder := newSSHTestRuntime(t)
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
			root := rootWithSSHForTest(rt, nil)

			args := append([]string{"ssh"}, tc.extraArgs...)
			args = append(args, "device-1234", "engineer@192.168.1.42")
			if err := execute(context.Background(), root, args...); err != nil {
				t.Fatalf("Run(ssh) error = %v", err)
			}

			wantCalls := 0
			if tc.wantBrokerHit {
				wantCalls = 1
			}
			if recorder.calls != wantCalls {
				t.Fatalf("broker calls = %d, want %d", recorder.calls, wantCalls)
			}
			if len(capture.invocations) != 1 {
				t.Fatalf("execSSH invocations = %d, want 1", len(capture.invocations))
			}
		})
	}
}

// TestSSHArgvShape covers the canonical argv layout assembled for ssh:
// "ssh -i <key> -o CertificateFile=<cert> <engineer args verbatim>". The
// wrapper prepends two flags and otherwise hands the rest of the command
// line to ssh unchanged — ssh handles user@host parsing, flag interspersing,
// and the optional remote command itself.
func TestSSHArgvShape(t *testing.T) {
	cases := []struct {
		name string
		args []string
		tail []string
	}{
		{
			name: "bare-host",
			args: []string{"ssh", "device-1234", "192.168.1.42"},
			tail: []string{"192.168.1.42"},
		},
		{
			name: "user-at-host",
			args: []string{"ssh", "device-1234", "alice@192.168.1.42"},
			tail: []string{"alice@192.168.1.42"},
		},
		{
			name: "passthrough-ssh-args",
			args: []string{"ssh", "device-1234", "engineer@192.168.1.42", "-L", "8080:localhost:80", "-v"},
			tail: []string{"engineer@192.168.1.42", "-L", "8080:localhost:80", "-v"},
		},
		{
			name: "ssh-flags-before-host",
			args: []string{"ssh", "device-1234", "-p", "2222", "engineer@192.168.1.42"},
			tail: []string{"-p", "2222", "engineer@192.168.1.42"},
		},
		{
			// `postern ssh <device>` with no extras — device-id is
			// appended as the destination so ssh has something to
			// connect to. Otherwise ssh would error out with
			// "missing host argument".
			name: "no-extra-args-appends-device-id",
			args: []string{"ssh", "device-1234"},
			tail: []string{"device-1234"},
		},
		{
			// Engineer-supplied flags-only passthrough still gets
			// the device-id appended — only the presence of a
			// host-shaped positional suppresses the auto-append.
			name: "flags-only-appends-device-id",
			args: []string{"ssh", "device-1234", "-v"},
			tail: []string{"-v", "device-1234"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, capture, recorder := newSSHTestRuntime(t)
			recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
				return broker.SSHCertIssueResponse{
					SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
				}
			}
			root := rootWithSSHForTest(rt, nil)

			if err := execute(context.Background(), root, tc.args...); err != nil {
				t.Fatalf("Run(ssh) error = %v", err)
			}

			certPath := filepath.Join(recorder.cacheDir, "default", "device-1234.cert")
			keyPath := filepath.Join(recorder.cacheDir, "default", "key")
			want := append([]string{
				"ssh",
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

// TestSSHTunnelHappyPath asserts the tunnel-mode flow composes broker
// MintSSHCert + broker OpenTunnel + securetunnel source-proxy start +
// ssh subprocess. The ssh argv carries the D3-pinned -p / HostName=127.0.0.1
// / NoHostAuthenticationForLocalhost=yes triad, retains the device-id
// (not 127.0.0.1) in the user@host slot so ~/.ssh/config blocks keep
// applying, and the proxy is Closed + Waited on ssh exit so no goroutines
// outlive the engineer's session.
func TestSSHTunnelHappyPath(t *testing.T) {
	rt, capture, recorder := newSSHTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	tunnelCalls := newTunnelCallRecorder()
	rt.tunnelOpener = tunnelCalls.opener("source-token-xyz", "tunnel-abc", "us-east-1", 480)
	proxy := newFakeSourceProxy(42424)
	rt.sourceProxyStarter = proxy.starter()
	root := rootWithSSHForTest(rt, nil)

	if err := execute(context.Background(), root, "ssh", "--tunnel", "device-1234", "engineer@target-host"); err != nil {
		t.Fatalf("Run(ssh --tunnel) error = %v", err)
	}

	if len(capture.invocations) != 1 {
		t.Fatalf("execSSH invocations = %d, want 1", len(capture.invocations))
	}
	argv := capture.lastArgv(t)
	wantFlags := []string{
		"-p", "42424",
		"-o", "HostName=127.0.0.1",
		"-o", "NoHostAuthenticationForLocalhost=yes",
	}
	for _, flag := range wantFlags {
		if !contains(argv, flag) {
			t.Fatalf("argv missing %q: %v", flag, argv)
		}
	}
	if got := argv[len(argv)-1]; got != "engineer@device-1234" {
		t.Fatalf("argv tail = %q, want %q (user@device-id preserved so ~/.ssh/config blocks apply)", got, "engineer@device-1234")
	}
	if proxy.closeCount() != 1 {
		t.Fatalf("proxy.Close calls = %d, want 1 (proxy must be torn down after ssh exits)", proxy.closeCount())
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

// TestSSHTunnelAppendsDeviceIDWhenNoHost covers the "engineer didn't pass
// a destination" shape: `postern ssh --tunnel <device>` (no user@host
// trailing). The wrapper appends device-id as the host so ssh has
// something to connect to via 127.0.0.1.
func TestSSHTunnelAppendsDeviceIDWhenNoHost(t *testing.T) {
	rt, capture, recorder := newSSHTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	tunnelCalls := newTunnelCallRecorder()
	rt.tunnelOpener = tunnelCalls.opener("source-token", "tunnel-id", "us-east-1", 480)
	proxy := newFakeSourceProxy(33333)
	rt.sourceProxyStarter = proxy.starter()
	root := rootWithSSHForTest(rt, nil)

	if err := execute(context.Background(), root, "ssh", "--tunnel", "device-1234"); err != nil {
		t.Fatalf("Run(ssh --tunnel) error = %v", err)
	}

	argv := capture.lastArgv(t)
	if got := argv[len(argv)-1]; got != "device-1234" {
		t.Fatalf("argv tail = %q, want %q", got, "device-1234")
	}
}

// TestSSHTunnelMaxLifetimeFlagFlowsToBroker covers the --max-lifetime plumb:
// the CLI duration converts to minutes and lands in the broker call site.
func TestSSHTunnelMaxLifetimeFlagFlowsToBroker(t *testing.T) {
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
			rt, _, recorder := newSSHTestRuntime(t)
			recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
				return broker.SSHCertIssueResponse{
					SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
				}
			}
			tunnelCalls := newTunnelCallRecorder()
			rt.tunnelOpener = tunnelCalls.opener("source-token", "tunnel-id", "us-east-1", 480)
			proxy := newFakeSourceProxy(40000)
			rt.sourceProxyStarter = proxy.starter()
			root := rootWithSSHForTest(rt, nil)

			err := execute(context.Background(), root, "ssh", "--tunnel", "--max-lifetime", tc.flagValue, "device-1234", "engineer@x")

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
				t.Fatalf("Run(ssh --tunnel) error = %v", err)
			}
			if got := tunnelCalls.lastMaxLifetime(); got != tc.wantMinutes {
				t.Fatalf("tunnelOpener max-lifetime = %d, want %d", got, tc.wantMinutes)
			}
		})
	}
}

// TestSSHTunnelSurfacesBrokerErrors covers the failure-mapping path: a
// broker /ssh/tunnel error (501 tunneling-disabled, 429 limit-exceeded,
// or any other status) flows out of the CLI verbatim so engineers see
// the structured broker reason. The source proxy must not be started
// on a broker error, and the ssh subprocess must not run.
func TestSSHTunnelSurfacesBrokerErrors(t *testing.T) {
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
			rt, capture, recorder := newSSHTestRuntime(t)
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
			root := rootWithSSHForTest(rt, nil)

			err := execute(context.Background(), root, "ssh", "--tunnel", "device-1234", "engineer@x")
			if err == nil {
				t.Fatalf("expected broker error, got nil")
			}
			if !errors.Is(err, tc.brokerErr) {
				t.Fatalf("Run(ssh --tunnel) error = %v, want chain through %v", err, tc.brokerErr)
			}
			if !strings.Contains(err.Error(), tc.wantInText) {
				t.Fatalf("error %q missing expected substring %q", err.Error(), tc.wantInText)
			}
			if proxy.startCount() != 0 {
				t.Fatalf("sourceProxyStarter called %d times, want 0 (broker error must short-circuit)", proxy.startCount())
			}
			if len(capture.invocations) != 0 {
				t.Fatalf("execSSH invocations = %d, want 0", len(capture.invocations))
			}
		})
	}
}

// TestSSHTunnelSourceProxyStartFailureCleansBrokerCall covers the path
// where /ssh/tunnel succeeds but the source proxy fails to start (e.g.
// bad SourceAccessToken; AWS subprotocol mismatch). The CLI must
// surface the proxy error and skip the ssh exec.
func TestSSHTunnelSourceProxyStartFailureCleansBrokerCall(t *testing.T) {
	rt, capture, recorder := newSSHTestRuntime(t)
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
	root := rootWithSSHForTest(rt, nil)

	err := execute(context.Background(), root, "ssh", "--tunnel", "device-1234", "engineer@x")
	if !errors.Is(err, startErr) {
		t.Fatalf("Run(ssh --tunnel) error = %v, want chain through %v", err, startErr)
	}
	if len(capture.invocations) != 0 {
		t.Fatalf("execSSH invocations = %d, want 0", len(capture.invocations))
	}
}

// TestSSHTunnelPreservesExitCode covers the exit-code propagation
// invariant: when ssh exits non-zero (network failure, auth rejection
// at the device, etc.) the cliapp surfaces the *exec.ExitError so the
// engineer's shell sees the same exit code ssh would have produced in
// direct-LAN mode. Proxy teardown still runs.
func TestSSHTunnelPreservesExitCode(t *testing.T) {
	rt, _, recorder := newSSHTestRuntime(t)
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
	proxy := newFakeSourceProxy(45111)
	rt.sourceProxyStarter = proxy.starter()
	sshErr := errors.New("ssh: exit status 255")
	rt.execSSH = func(context.Context, []string, io.Reader, io.Writer, io.Writer) error {
		return sshErr
	}
	root := rootWithSSHForTest(rt, nil)

	err := execute(context.Background(), root, "ssh", "--tunnel", "device-1234", "engineer@x")
	if !errors.Is(err, sshErr) {
		t.Fatalf("Run(ssh --tunnel) error = %v, want chain through %v", err, sshErr)
	}
	if proxy.closeCount() != 1 || proxy.waitCount() != 1 {
		t.Fatalf("teardown skipped on ssh failure: close=%d wait=%d", proxy.closeCount(), proxy.waitCount())
	}
}

// TestSSHTunnelVerboseRedactsSourceAccessToken covers invariant T: the
// source access token never appears in CLI verbose output, even though
// the engineer asked for diagnostics. The token is bearer-equivalent
// for the AWS WebSocket dial; surfacing it in stderr would expose it
// to terminal scrollback / log capture.
func TestSSHTunnelVerboseRedactsSourceAccessToken(t *testing.T) {
	rt, _, recorder := newSSHTestRuntime(t)
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
	proxy := newFakeSourceProxy(40000)
	rt.sourceProxyStarter = proxy.starter()
	root := rootWithSSHForTest(rt, nil)

	var stderr bytes.Buffer
	root.SetErr(&stderr)
	if err := execute(context.Background(), root, "ssh", "--tunnel", "-v", "device-1234", "engineer@x"); err != nil {
		t.Fatalf("Run(ssh --tunnel -v) error = %v", err)
	}

	if strings.Contains(stderr.String(), secretToken) {
		t.Fatalf("source access token leaked into verbose stderr:\n%s", stderr.String())
	}
	// The verbose output SHOULD still surface the tunnel id + region
	// (engineer-actionable diagnostic).
	if !strings.Contains(stderr.String(), "tunnel-abc") {
		t.Fatalf("verbose stderr missing tunnel id diagnostic:\n%s", stderr.String())
	}
}

// TestSSHTunnelExtractsServiceIDAndRegion covers the argument-shape
// contract with securetunnel: the broker's resolved Region + the
// SourceAccessToken + DefaultServiceID ("SSH") land in the
// SourceProxyOptions, and the proxy starter is invoked with those.
func TestSSHTunnelExtractsServiceIDAndRegion(t *testing.T) {
	rt, _, recorder := newSSHTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	rt.tunnelOpener = func(context.Context, ResolvedProfile, string, string, int32) (broker.TunnelOpenResponse, error) {
		return broker.TunnelOpenResponse{
			TunnelID:           "tunnel-id",
			SourceAccessToken:  "source-token-zzz",
			Region:             "eu-west-2",
			MaxLifetimeMinutes: 240,
		}, nil
	}
	proxy := newFakeSourceProxy(40001)
	rt.sourceProxyStarter = proxy.starter()
	root := rootWithSSHForTest(rt, nil)

	if err := execute(context.Background(), root, "ssh", "--tunnel", "device-1234", "engineer@x"); err != nil {
		t.Fatalf("Run(ssh --tunnel) error = %v", err)
	}

	if got := proxy.lastOptions().Region; got != "eu-west-2" {
		t.Fatalf("SourceProxyOptions.Region = %q, want %q", got, "eu-west-2")
	}
	if got := proxy.lastOptions().SourceAccessToken; got != "source-token-zzz" {
		t.Fatalf("SourceProxyOptions.SourceAccessToken not passed through")
	}
	if got := proxy.lastOptions().ServiceID; got != securetunnel.DefaultServiceID {
		t.Fatalf("SourceProxyOptions.ServiceID = %q, want %q", got, securetunnel.DefaultServiceID)
	}
}

// TestSSHUserFlagAddsDashL covers the new --user flag: it injects
// `-l <user>` into the ssh argv and wins over any other signal.
func TestSSHUserFlagAddsDashL(t *testing.T) {
	rt, capture, recorder := newSSHTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	root := rootWithSSHForTest(rt, nil)

	if err := execute(context.Background(), root, "ssh", "--user", "root", "device-1234"); err != nil {
		t.Fatalf("Run(ssh --user) error = %v", err)
	}

	argv := capture.lastArgv(t)
	idx := -1
	for i, tok := range argv {
		if tok == "-l" {
			idx = i
			break
		}
	}
	if idx < 0 {
		t.Fatalf("argv missing -l flag: %v", argv)
	}
	if argv[idx+1] != "root" {
		t.Fatalf("argv[%d+1] = %q, want %q", idx, argv[idx+1], "root")
	}
}

// TestSSHUserResolutionSkippedWhenPassthroughHasUser locks the
// no-conflict rule: if the engineer already passes user@host (or -l)
// in the passthrough args, postern does NOT also append its own -l.
func TestSSHUserResolutionSkippedWhenPassthroughHasUser(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "user-at-host", args: []string{"ssh", "device-1234", "alice@192.168.1.42"}},
		{name: "dash-l", args: []string{"ssh", "device-1234", "-l", "alice", "192.168.1.42"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, capture, recorder := newSSHTestRuntime(t)
			// Configure a profile default to prove resolveUser would
			// emit something if the passthrough check didn't suppress.
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
			root := rootWithSSHForTest(rt, nil)

			if err := execute(context.Background(), root, tc.args...); err != nil {
				t.Fatalf("Run(ssh) error = %v", err)
			}

			argv := capture.lastArgv(t)
			// postern must not have injected its own -l opsteam.
			// (If the engineer wrote -l alice themselves it's
			// already in the passthrough and is fine.)
			for i, tok := range argv {
				if tok == "-l" && i+1 < len(argv) && argv[i+1] == "opsteam" {
					t.Fatalf("postern injected -l opsteam despite passthrough user: %v", argv)
				}
			}
		})
	}
}

// TestSSHProfileDefaultEmitsDashL covers the precedence-end-to-end
// case where no --user flag is set, the passthrough is bare-host, no
// persistent stanza is registered, but the profile has a non-default
// DefaultSSHUser. We emit -l <profile-default> because it's a real
// signal (more specific than the built-in fallback).
func TestSSHProfileDefaultEmitsDashL(t *testing.T) {
	rt, capture, recorder := newSSHTestRuntime(t)
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
	root := rootWithSSHForTest(rt, nil)

	if err := execute(context.Background(), root, "ssh", "device-1234"); err != nil {
		t.Fatalf("Run(ssh) error = %v", err)
	}

	argv := capture.lastArgv(t)
	found := false
	for i, tok := range argv {
		if tok == "-l" && i+1 < len(argv) && argv[i+1] == "opsteam" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("argv missing -l opsteam (profile default should win when nothing else is set): %v", argv)
	}
}

// TestSSHPersistentStanzaUserEmitsDashL covers the integration of
// resolveUser into the ssh path: with a persistent <device> stanza
// registered in the Postern-managed ssh.conf, the stanza's User
// directive flows into the ssh argv via -l, overriding the profile
// default.
func TestSSHPersistentStanzaUserEmitsDashL(t *testing.T) {
	rt, capture, recorder := newSSHTestRuntime(t)
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
	root := rootWithSSHForTest(rt, nil)

	if err := execute(context.Background(), root, "ssh", "device-1234"); err != nil {
		t.Fatalf("Run(ssh) error = %v", err)
	}

	argv := capture.lastArgv(t)
	found := false
	for i, tok := range argv {
		if tok == "-l" && i+1 < len(argv) && argv[i+1] == "fleet-admin" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("argv missing -l fleet-admin (persistent stanza User should win over profile default): %v", argv)
	}
	for i, tok := range argv {
		if tok == "-l" && i+1 < len(argv) && argv[i+1] == "opsteam" {
			t.Fatalf("argv carries profile default despite persistent stanza: %v", argv)
		}
	}
}

// TestSSHBuiltInDefaultDoesNotEmitDashL pins the implicit-fallback
// rule: when nothing is configured (no --user, no stanza, no profile
// default_ssh_user) resolveUser returns explicit=false and ssh skips
// emitting -l so a `Host *` User directive in the engineer's
// ~/.ssh/config keeps applying. This holds even though the resolved
// value happens to be the built-in DefaultSSHUser string ("engineer")
// — the explicit bool, not a value-match sentinel, drives the choice.
func TestSSHBuiltInDefaultDoesNotEmitDashL(t *testing.T) {
	rt, capture, recorder := newSSHTestRuntime(t)
	recorder.response = func(request broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, recorder.ca.mintCert(t, mustParseRequestKey(t, request.PublicKey), "device-1234", time.Now().Add(-time.Minute), time.Now().Add(12*time.Hour))),
		}
	}
	root := rootWithSSHForTest(rt, nil)

	if err := execute(context.Background(), root, "ssh", "device-1234"); err != nil {
		t.Fatalf("Run(ssh) error = %v", err)
	}

	argv := capture.lastArgv(t)
	for _, tok := range argv {
		if tok == "-l" {
			t.Fatalf("argv unexpectedly carries -l despite no configured user: %v", argv)
		}
	}
}

// TestSSHExplicitProfileEngineerEmitsDashL pins the contrapositive of
// the implicit-fallback rule: when the engineer explicitly chose
// "engineer" as their profile default_ssh_user (a legitimate fleet
// username, not a sentinel), -l engineer IS emitted. Same applies if
// they explicitly typed `--user engineer` or wrote `User engineer` in
// an add-host stanza; the explicit signal flows through to ssh.
func TestSSHExplicitProfileEngineerEmitsDashL(t *testing.T) {
	rt, capture, recorder := newSSHTestRuntime(t)
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
	root := rootWithSSHForTest(rt, nil)

	if err := execute(context.Background(), root, "ssh", "device-1234"); err != nil {
		t.Fatalf("Run(ssh) error = %v", err)
	}

	argv := capture.lastArgv(t)
	found := false
	for i, tok := range argv {
		if tok == "-l" && i+1 < len(argv) && argv[i+1] == DefaultSSHUser {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("argv missing -l %s (explicit profile default_ssh_user: %s must emit): %v", DefaultSSHUser, DefaultSSHUser, argv)
	}
}

func TestSSHAuthFailureNamesLogin(t *testing.T) {
	tokenErr := errors.New("no token cached")
	rt, capture, recorder := newSSHTestRuntime(t)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "", tokenErr
	}
	recorder.response = func(broker.SSHCertIssueRequest) broker.SSHCertIssueResponse {
		t.Fatal("broker must not be called when access-token retrieval fails")
		return broker.SSHCertIssueResponse{}
	}
	root := rootWithSSHForTest(rt, nil)

	err := execute(context.Background(), root, "ssh", "device-1234", "engineer@192.168.1.42")
	if !errors.Is(err, ErrMintNoAuth) {
		t.Fatalf("Run(ssh) error = %v, want ErrMintNoAuth", err)
	}
	if !errors.Is(err, tokenErr) {
		t.Fatalf("Run(ssh) error = %v, want underlying token error preserved", err)
	}
	if !strings.Contains(err.Error(), `"postern" --profile "default" login`) {
		t.Fatalf("Run(ssh) error = %v, want login hint", err)
	}
	if len(capture.invocations) != 0 {
		t.Fatalf("execSSH invocations = %d, want 0", len(capture.invocations))
	}
}

func TestSSHSurfacesBrokerErrors(t *testing.T) {
	brokerErr := errors.New("policy denied: device not in fleet")
	rt, capture, recorder := newSSHTestRuntime(t)
	rt.sshCertRequester = func(context.Context, ResolvedProfile, string, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		recorder.calls++
		return broker.SSHCertIssueResponse{}, brokerErr
	}
	root := rootWithSSHForTest(rt, nil)

	err := execute(context.Background(), root, "ssh", "device-1234", "engineer@192.168.1.42")
	if !errors.Is(err, brokerErr) {
		t.Fatalf("Run(ssh) error = %v, want broker error", err)
	}
	if len(capture.invocations) != 0 {
		t.Fatalf("execSSH invocations = %d, want 0", len(capture.invocations))
	}
}

// sshExecCapture records argv passed to the runtime's execSSH hook without
// actually spawning ssh. Tests assert on the argv shape instead of attempting
// an end-to-end ssh round-trip, which would need a live sshd.
type sshExecCapture struct {
	invocations [][]string
}

func (c *sshExecCapture) hook() execSSHFunc {
	return func(_ context.Context, argv []string, _ io.Reader, _, _ io.Writer) error {
		argvCopy := append([]string(nil), argv...)
		c.invocations = append(c.invocations, argvCopy)
		return nil
	}
}

func (c *sshExecCapture) lastArgv(t *testing.T) []string {
	t.Helper()
	if len(c.invocations) == 0 {
		t.Fatal("execSSH was never invoked")
	}
	return c.invocations[len(c.invocations)-1]
}

// brokerRecorder tracks broker calls and renders a configurable response so
// each test can shape the response without rewriting the closure plumbing.
type brokerRecorder struct {
	ca       *mintTestCA
	cacheDir string
	calls    int
	response func(broker.SSHCertIssueRequest) broker.SSHCertIssueResponse
}

// newSubcommandTestRuntime builds the common runtime + broker recorder
// every ssh/scp subcommand test needs: tmpdir cache, tmpdir ssh.conf,
// fresh mint CA, recording broker, fixed access token, sane profile
// resolver. Callers (newSSHTestRuntime, newSCPTestRuntime) attach the
// per-subcommand exec capture themselves so test failures can name the
// right seam (`execSSH was never invoked` vs `execSCP was never
// invoked`).
func newSubcommandTestRuntime(t *testing.T) (runtime, *brokerRecorder) {
	t.Helper()
	cacheDir := t.TempDir()
	sshConfPath := filepath.Join(t.TempDir(), "ssh.conf")
	ca := newMintTestCA(t)
	recorder := &brokerRecorder{ca: ca, cacheDir: cacheDir}

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
		recorder.calls++
		if recorder.response == nil {
			t.Fatal("brokerRecorder.response not configured")
		}
		return recorder.response(request), nil
	}
	// Isolate the openSSHConfWriter under a tmpdir so user-resolution
	// stanza lookups can't accidentally read the engineer's real
	// ~/.postern/ssh.conf during tests.
	rt.openSSHConfWriter = func() (*sshconf.Writer, error) {
		return sshconf.NewWriter(sshConfPath), nil
	}
	return rt, recorder
}

func newSSHTestRuntime(t *testing.T) (runtime, *sshExecCapture, *brokerRecorder) {
	rt, recorder := newSubcommandTestRuntime(t)
	capture := &sshExecCapture{}
	rt.execSSH = capture.hook()
	return rt, capture, recorder
}

// seedCachedCert primes the cache with a valid cert for device good for
// validFor duration from now, using the same Store the handler will open.
// The cert is signed over the profile's stored subject key so PutCert
// accepts it.
func seedCachedCert(t *testing.T, cacheDir string, ca *mintTestCA, device string, validFor time.Duration) {
	t.Helper()
	store, err := certcache.OpenStore(cacheDir, "default")
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	cert := ca.mintCert(t, profilePub, device, time.Now().Add(-time.Minute), time.Now().Add(validFor))
	if err := store.PutCert(device, cert); err != nil {
		t.Fatalf("PutCert() error = %v", err)
	}
}

// rootWithSSHForTest builds a minimal cobra root carrying only the ssh
// subcommand. Mirrors the rootWith*ForTest helpers in sibling files.
func rootWithSSHForTest(rt runtime, stdout *bytes.Buffer) *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	if stdout != nil {
		root.SetOut(stdout)
	}
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.AddCommand(sshCommand(rt))
	return root
}

// tunnelCallRecorder captures every broker.OpenTunnel call the cliapp
// made along with the response shape the caller wants the fake broker
// to return. Tests use it to assert the --max-lifetime plumbing, the
// device-id propagation, and the broker call count.
type tunnelCallRecorder struct {
	count     int
	device    string
	lifetime  int32
	responder func() (broker.TunnelOpenResponse, error)
}

func newTunnelCallRecorder() *tunnelCallRecorder {
	return &tunnelCallRecorder{}
}

// opener returns a tunnelOpenerFunc that records each call and returns
// the canned TunnelOpenResponse. The four-value shape mirrors the
// broker's response surface (TunnelID + SourceAccessToken + Region +
// MaxLifetimeMinutes) so tests don't construct one inline.
func (r *tunnelCallRecorder) opener(sourceToken, tunnelID, region string, maxLifetimeMinutes int32) tunnelOpenerFunc {
	return func(_ context.Context, _ ResolvedProfile, _, deviceID string, lifetime int32) (broker.TunnelOpenResponse, error) {
		r.count++
		r.device = deviceID
		r.lifetime = lifetime
		return broker.TunnelOpenResponse{
			TunnelID:           tunnelID,
			SourceAccessToken:  sourceToken,
			Region:             region,
			MaxLifetimeMinutes: maxLifetimeMinutes,
		}, nil
	}
}

func (r *tunnelCallRecorder) calls() int             { return r.count }
func (r *tunnelCallRecorder) lastDeviceID() string   { return r.device }
func (r *tunnelCallRecorder) lastMaxLifetime() int32 { return r.lifetime }

// fakeSourceProxy stands in for *securetunnel.SourceProxy in cliapp
// tests. Implements the sourceProxy interface plus exposes start /
// close / wait counters and the last-seen SourceProxyOptions so tests
// can assert the cliapp passed the right region + service id + token
// to the starter. A fixed LocalPort is returned per fake instance so
// tests can assert ssh argv carries the right -p value without binding
// a real listener. Counters are guarded by mu so the TN-F tunnel-open
// tests — which read counts concurrently while a goroutine drives the
// hold-open subcommand — don't race.
type fakeSourceProxy struct {
	mu          sync.Mutex
	port        int
	starts      int
	closes      int
	waits       int
	lastOpts    securetunnel.SourceProxyOptions
	startError  error
	waitError   error
	closeReturn error
}

func newFakeSourceProxy(port int) *fakeSourceProxy {
	return &fakeSourceProxy{port: port}
}

// starter returns a sourceProxyStarterFunc that records the options
// and returns the fake handle. Tests assign it to rt.sourceProxyStarter.
func (p *fakeSourceProxy) starter() sourceProxyStarterFunc {
	return func(_ context.Context, options securetunnel.SourceProxyOptions) (sourceProxy, error) {
		p.mu.Lock()
		p.starts++
		p.lastOpts = options
		startErr := p.startError
		p.mu.Unlock()
		if startErr != nil {
			return nil, startErr
		}
		return &fakeSourceProxyHandle{parent: p}, nil
	}
}

func (p *fakeSourceProxy) startCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.starts
}
func (p *fakeSourceProxy) closeCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closes
}
func (p *fakeSourceProxy) waitCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waits
}
func (p *fakeSourceProxy) lastOptions() securetunnel.SourceProxyOptions {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastOpts
}

// fakeSourceProxyHandle is the per-call handle the fake starter
// returns. Keeping the count fields on the parent struct lets tests
// assert across the full lifecycle even after the cliapp drops the
// handle.
type fakeSourceProxyHandle struct {
	parent *fakeSourceProxy
}

func (h *fakeSourceProxyHandle) LocalPort() int { return h.parent.port }
func (h *fakeSourceProxyHandle) Wait() error {
	h.parent.mu.Lock()
	h.parent.waits++
	waitErr := h.parent.waitError
	h.parent.mu.Unlock()
	return waitErr
}
func (h *fakeSourceProxyHandle) Close() error {
	h.parent.mu.Lock()
	h.parent.closes++
	closeErr := h.parent.closeReturn
	h.parent.mu.Unlock()
	return closeErr
}

// contains reports whether argv carries the given element. Helper to
// keep argv-shape assertions concise; equivalent to slices.Contains
// but without the import dance for the older Go floor.
func contains(argv []string, want string) bool {
	for _, token := range argv {
		if token == want {
			return true
		}
	}
	return false
}
