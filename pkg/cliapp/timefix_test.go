package cliapp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/certcache"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
)

// canonicalTestNonce is the base64url-encoded 32-byte nonce the fake device
// emits in tests. Computed once so each test can assert on the same value.
var canonicalTestNonce = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xAB}, 32))

// canonicalTestDeviceClock is the RFC3339 value the fake device emits as
// its second stdout line. The value itself is arbitrary; what matters is
// that the format matches the production verifier's emission shape.
var canonicalTestDeviceClock = "2026-05-13T12:00:00Z"

// TestTimefixHappyPath exercises the full mint → connect → nonce → broker →
// JWS pipeline. Uses the realBrokerHarness so the cert that flows through
// is signed by the real broker's IssueSSHCert (exercising the D12 timefix
// cert-shape branch end-to-end), not a hand-fabricated cert from a fake.
func TestTimefixHappyPath(t *testing.T) {
	rt, harness := newTimefixTestRuntimeRealBroker(t)
	harness.jws = "header.payload.signature"

	root := rootWithTimefixForTest(rt, nil)
	if err := execute(context.Background(), root, "timefix", "device-1234"); err != nil {
		t.Fatalf("Run(timefix) error = %v", err)
	}

	if got, want := harness.timefixCalls, 1; got != want {
		t.Fatalf("execSSHTimefix calls = %d, want %d", got, want)
	}
	if got, want := harness.timePayloadCalls, 1; got != want {
		t.Fatalf("timePayloadFetch calls = %d, want %d", got, want)
	}
	if got, want := harness.lastNonceSupplied, canonicalTestNonce; got != want {
		t.Fatalf("nonce supplied to broker = %q, want %q", got, want)
	}
	if got, want := harness.lastJWSWritten, "header.payload.signature"; got != want {
		t.Fatalf("JWS written to device stdin = %q, want %q", got, want)
	}

	// Cert mint should request a timefix-typed principal so the broker
	// routes the cert through MintTimefixCert policy + cert principal
	// shape.
	if got, want := harness.lastCertRequest.PrincipalType, broker.PrincipalTypeTimefix; got != want {
		t.Fatalf("cert principal type = %q, want %q", got, want)
	}

	// The cert blob the runtime wrote to the tempfile was minted by the
	// real broker pipeline. Parse it back and confirm the D12 cert shape
	// flowed through end-to-end (1970→3000 validity, force-command, no
	// permit-pty).
	if harness.observedCertContents == "" {
		t.Fatal("harness did not capture the minted cert contents")
	}
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(harness.observedCertContents))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(minted cert) error = %v", err)
	}
	cert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		t.Fatalf("minted cert type = %T, want *ssh.Certificate", parsedKey)
	}
	if got, want := cert.CriticalOptions["force-command"], "/usr/sbin/timefix-apply"; got != want {
		t.Fatalf("force-command = %q, want %q", got, want)
	}
	if len(cert.Extensions) != 0 {
		t.Fatalf("extensions = %#v, want empty (no permit-pty on timefix cert)", cert.Extensions)
	}
	// The real broker pipeline resolves the engineer-typed device_id
	// through the registry to a canonical serial; the test registry maps
	// any input to "TESTSERIAL", so the cert principal carries that.
	wantPrincipal := "device-TESTSERIAL-timefix"
	if got := strings.Join(cert.ValidPrincipals, ","); got != wantPrincipal {
		t.Fatalf("principals = %q, want %q", got, wantPrincipal)
	}
}

// TestTimefixMintFailure asserts the broker's cert-mint rejection short-
// circuits the flow: no SSH spawn, no time-payload fetch, no tempfile left
// behind.
func TestTimefixMintFailure(t *testing.T) {
	rt, harness := newTimefixTestRuntime(t)
	brokerErr := errors.New("policy denied: device not in timefix group")
	rt.sshCertRequester = func(context.Context, ResolvedProfile, string, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		return broker.SSHCertIssueResponse{}, brokerErr
	}

	root := rootWithTimefixForTest(rt, nil)
	err := execute(context.Background(), root, "timefix", "device-1234")
	if !errors.Is(err, brokerErr) {
		t.Fatalf("Run(timefix) error = %v, want broker error", err)
	}
	if harness.timefixCalls != 0 {
		t.Fatalf("execSSHTimefix calls = %d, want 0 on mint failure", harness.timefixCalls)
	}
	if harness.timePayloadCalls != 0 {
		t.Fatalf("timePayloadFetch calls = %d, want 0 on mint failure", harness.timePayloadCalls)
	}
}

// TestTimefixNonceMalformed exercises both the empty-nonce and bad-base64url
// paths: the supplier callback inside runTimefix should reject the
// device-emitted nonce before any broker call goes out so a clearly-broken
// device side surfaces a CLI-shaped error rather than a broker 400.
func TestTimefixNonceMalformed(t *testing.T) {
	cases := []struct {
		name   string
		emit   string
		wantIs error
	}{
		{name: "empty-line", emit: "", wantIs: ErrTimefixEmptyNonce},
		{name: "not-base64url", emit: "$$$not-base64$$$", wantIs: ErrTimefixMalformedNonce},
		{name: "wrong-decoded-length", emit: base64.RawURLEncoding.EncodeToString(make([]byte, 16)), wantIs: ErrTimefixMalformedNonce},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, harness := newTimefixTestRuntime(t)
			harness.deviceNonce = tc.emit

			root := rootWithTimefixForTest(rt, nil)
			err := execute(context.Background(), root, "timefix", "device-1234")
			if err == nil {
				t.Fatalf("Run(timefix) returned nil error, want %v", tc.wantIs)
			}
			if !errors.Is(err, tc.wantIs) {
				t.Fatalf("Run(timefix) error = %v, want errors.Is(%v)", err, tc.wantIs)
			}
			if harness.timePayloadCalls != 0 {
				t.Fatalf("timePayloadFetch calls = %d, want 0 on malformed nonce", harness.timePayloadCalls)
			}
		})
	}
}

// TestTimefixTimePayloadFailure asserts a broker rejection of
// /ssh/time-payload (404 / 403 / 429) propagates as a CLI error and prevents
// the JWS from reaching the device.
func TestTimefixTimePayloadFailure(t *testing.T) {
	rt, harness := newTimefixTestRuntime(t)
	timePayloadErr := errors.New("status 429 Too Many Requests: rate-limited")
	rt.timePayloadFetch = func(_ context.Context, _ ResolvedProfile, _, _, nonce string) (string, error) {
		harness.timePayloadCalls++
		harness.lastNonceSupplied = nonce
		return "", timePayloadErr
	}

	root := rootWithTimefixForTest(rt, nil)
	err := execute(context.Background(), root, "timefix", "device-1234")
	if !errors.Is(err, timePayloadErr) {
		t.Fatalf("Run(timefix) error = %v, want broker time-payload error", err)
	}
	if harness.lastJWSWritten != "" {
		t.Fatalf("JWS written to device = %q, want empty (no JWS on broker rejection)", harness.lastJWSWritten)
	}
}

// TestTimefixDeviceSideFailure asserts the device's non-zero exit code
// surfaces in the CLI error so an engineer can correlate against
// timefix-apply's invariant-P exit codes (3 = alg mismatch, 5 = claim
// validation failure, etc.).
func TestTimefixDeviceSideFailure(t *testing.T) {
	rt, harness := newTimefixTestRuntime(t)
	harness.deviceExitCode = 5
	harness.deviceExitErr = errors.New("verifier rejected JWS: nonce mismatch")

	root := rootWithTimefixForTest(rt, nil)
	err := execute(context.Background(), root, "timefix", "device-1234")
	if err == nil {
		t.Fatal("Run(timefix) returned nil error, want device-side failure")
	}
	if !strings.Contains(err.Error(), "device exit 5") {
		t.Fatalf("Run(timefix) error = %v, want device exit code surfaced", err)
	}
}

// TestTimefixTempCertCleanup is the load-bearing assertion for the
// no-cache property: the per-invocation tempfile must be removed on every
// exit path. The timefix cert is 1970→3000 valid so a cached artifact
// would sit indefinitely on disk for no operational benefit. We capture
// the cert path the streaming exec saw, then assert it doesn't exist
// after the call returns. Two arms: success and device-side failure.
func TestTimefixTempCertCleanup(t *testing.T) {
	cases := []struct {
		name     string
		exitCode int
		exitErr  error
		wantErr  bool
	}{
		{name: "success-path", exitCode: 0, exitErr: nil, wantErr: false},
		{name: "device-failure-path", exitCode: 5, exitErr: errors.New("device rejected"), wantErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, harness := newTimefixTestRuntime(t)
			harness.deviceExitCode = tc.exitCode
			harness.deviceExitErr = tc.exitErr

			root := rootWithTimefixForTest(rt, nil)
			err := execute(context.Background(), root, "timefix", "device-1234")
			if tc.wantErr != (err != nil) {
				t.Fatalf("Run(timefix) error = %v, wantErr = %v", err, tc.wantErr)
			}

			if harness.observedCertPath == "" {
				t.Fatal("execSSHTimefix never saw a cert path; harness wiring is broken")
			}
			if _, statErr := os.Stat(harness.observedCertPath); !os.IsNotExist(statErr) {
				t.Fatalf("tempfile %q still exists after timefix returned (stat err = %v); no-cache cleanup invariant broken", harness.observedCertPath, statErr)
			}
		})
	}
}

// TestTimefixTempCertCleanupOnMintFailure covers the early-error path: the
// broker rejects the cert mint before any tempfile is created, so the
// "cert path never existed" branch of the no-cache invariant holds by construction. We
// assert the harness never sees a cert path (no SSH spawn) AND the cert
// dir under the OS temp dir doesn't carry stray postern-timefix-*.cert
// files from this test process.
func TestTimefixTempCertCleanupOnMintFailure(t *testing.T) {
	rt, harness := newTimefixTestRuntime(t)
	rt.sshCertRequester = func(context.Context, ResolvedProfile, string, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		return broker.SSHCertIssueResponse{}, errors.New("broker said no")
	}

	root := rootWithTimefixForTest(rt, nil)
	if err := execute(context.Background(), root, "timefix", "device-1234"); err == nil {
		t.Fatal("Run(timefix) returned nil error, want broker rejection")
	}

	if harness.observedCertPath != "" {
		t.Fatalf("execSSHTimefix observed cert path %q on mint failure; ssh must not be spawned", harness.observedCertPath)
	}
}

// TestTimefixUsesProfileSubjectKey asserts the cert mint reuses the
// engineer's persistent profile subject key (from certcache.ProfileKey)
// rather than minting a fresh per-call keypair. Two timefix invocations
// against the same cache must see the same public key on the broker side.
func TestTimefixUsesProfileSubjectKey(t *testing.T) {
	rt, harness := newTimefixTestRuntime(t)

	root := rootWithTimefixForTest(rt, nil)
	if err := execute(context.Background(), root, "timefix", "device-1234"); err != nil {
		t.Fatalf("Run(timefix) error = %v", err)
	}
	firstKey := harness.lastCertRequest.PublicKey

	if err := execute(context.Background(), root, "timefix", "device-1234"); err != nil {
		t.Fatalf("Run(timefix) second invocation error = %v", err)
	}
	secondKey := harness.lastCertRequest.PublicKey

	if firstKey == "" {
		t.Fatal("first invocation public key is empty; harness did not record cert request")
	}
	if firstKey != secondKey {
		t.Fatalf("public keys differ across invocations:\n first  = %q\n second = %q\n(profile subject key must be reused; a fresh-per-call key would defeat the persistent-engineer-identity property)", firstKey, secondKey)
	}

	// Cross-check: the recorded public key matches the persistent profile
	// key in the test cache store, not some throwaway ephemeral derived
	// from a per-call generator.
	store, err := certcache.OpenStore(harness.cacheDir, "default")
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	_, profilePub, err := store.ProfileKey()
	if err != nil {
		t.Fatalf("ProfileKey() error = %v", err)
	}
	wantPubKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(profilePub)))
	if firstKey != wantPubKey {
		t.Fatalf("public key recorded = %q, want persistent profile pub %q", firstKey, wantPubKey)
	}
}

// TestTimefixIPFlagPassesHostNameOverride locks the --ip flag wiring: the
// flag adds exactly one -o HostName=<value> entry to the ssh argv while
// keeping the connect target as timefix@<device-id> so any Host <device-id>
// stanza in ~/.ssh/config still applies its directives. Absent the flag,
// no -o HostName= entry appears at all.
func TestTimefixIPFlagPassesHostNameOverride(t *testing.T) {
	t.Run("with --ip adds HostName override", func(t *testing.T) {
		rt, harness := newTimefixTestRuntime(t)
		root := rootWithTimefixForTest(rt, nil)
		if err := execute(context.Background(), root, "timefix", "--ip", "10.0.0.5", "device-1234"); err != nil {
			t.Fatalf("Run(timefix --ip) error = %v", err)
		}
		hits := 0
		for i, arg := range harness.observedArgv {
			if arg == "-o" && i+1 < len(harness.observedArgv) && harness.observedArgv[i+1] == "HostName=10.0.0.5" {
				hits++
			}
		}
		if hits != 1 {
			t.Fatalf("HostName=10.0.0.5 occurrences = %d, want 1; argv = %v", hits, harness.observedArgv)
		}
		// Connect target stays timefix@<device-id>, not timefix@<ip>.
		if got, want := harness.observedArgv[len(harness.observedArgv)-1], "timefix@device-1234"; got != want {
			t.Fatalf("connect target = %q, want %q", got, want)
		}
	})

	t.Run("without --ip omits HostName override", func(t *testing.T) {
		rt, harness := newTimefixTestRuntime(t)
		root := rootWithTimefixForTest(rt, nil)
		if err := execute(context.Background(), root, "timefix", "device-1234"); err != nil {
			t.Fatalf("Run(timefix) error = %v", err)
		}
		for i, arg := range harness.observedArgv {
			if arg == "-o" && i+1 < len(harness.observedArgv) && strings.HasPrefix(harness.observedArgv[i+1], "HostName=") {
				t.Fatalf("HostName override present without --ip flag: argv = %v", harness.observedArgv)
			}
		}
	})
}

// TestTimefixQuietSuppressesProgress locks the verbose-by-default + --quiet
// opt-out behavior: an invocation without --quiet emits the expected
// progress lines on stderr; an invocation with --quiet emits nothing on
// stderr on the success path.
func TestTimefixQuietSuppressesProgress(t *testing.T) {
	t.Run("default is verbose", func(t *testing.T) {
		rt, _ := newTimefixTestRuntime(t)
		stderr := captureCmdStderr(t, rt, "timefix", "device-1234")
		if !strings.Contains(stderr, "minting timefix cert for") {
			t.Fatalf("verbose-default stderr missing cert-mint line: %q", stderr)
		}
		if !strings.Contains(stderr, "device clock: "+canonicalTestDeviceClock) {
			t.Fatalf("verbose-default stderr missing device-clock surfacing: %q", stderr)
		}
		if !strings.Contains(stderr, "complete") {
			t.Fatalf("verbose-default stderr missing completion line: %q", stderr)
		}
	})

	t.Run("--quiet suppresses progress", func(t *testing.T) {
		rt, _ := newTimefixTestRuntime(t)
		stderr := captureCmdStderr(t, rt, "timefix", "--quiet", "device-1234")
		if stderr != "" {
			t.Fatalf("--quiet stderr = %q, want empty", stderr)
		}
	})

	t.Run("-v short flag is removed", func(t *testing.T) {
		rt, _ := newTimefixTestRuntime(t)
		root := rootWithTimefixForTest(rt, nil)
		// cobra surfaces unknown flags through Execute's returned error.
		err := execute(context.Background(), root, "timefix", "-v", "device-1234")
		if err == nil {
			t.Fatal("Run(timefix -v) returned nil error, want unknown-flag error")
		}
		if !strings.Contains(err.Error(), "unknown shorthand flag") && !strings.Contains(err.Error(), "unknown flag") {
			t.Fatalf("Run(timefix -v) error = %v, want unknown-flag message", err)
		}
	})
}

// captureCmdStderr runs the timefix subcommand against a freshly assembled
// root, captures stderr into a buffer, and returns its contents.
func captureCmdStderr(t *testing.T, rt runtime, args ...string) string {
	t.Helper()
	var stderr bytes.Buffer
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.SetErr(&stderr)
	root.AddCommand(timefixCommand(rt))
	if err := execute(context.Background(), root, args...); err != nil {
		t.Fatalf("Run(timefix) error = %v", err)
	}
	return stderr.String()
}

// TestTimefixSSHArgvShape covers the canonical argv layout the timefix
// streaming exec receives: ssh with -i / -o options matching the engineer-
// facing ssh subcommand, plus -T to disable TTY allocation and the
// "timefix@<host>" destination so sshd's Match-User-timefix ForceCommand
// fires the verifier binary.
func TestTimefixSSHArgvShape(t *testing.T) {
	rt, harness := newTimefixTestRuntime(t)

	root := rootWithTimefixForTest(rt, nil)
	if err := execute(context.Background(), root, "timefix", "device-1234"); err != nil {
		t.Fatalf("Run(timefix) error = %v", err)
	}

	if harness.observedArgv == nil {
		t.Fatal("execSSHTimefix did not capture argv")
	}
	// The cert path is dynamic (tempfile under the OS temp dir) so we
	// assert the surrounding shape and check the cert flag separately.
	if got, want := harness.observedArgv[0], "ssh"; got != want {
		t.Fatalf("argv[0] = %q, want %q", got, want)
	}
	wantTail := []string{
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"-T",
		"timefix@device-1234",
	}
	if got := harness.observedArgv[len(harness.observedArgv)-len(wantTail):]; !reflect.DeepEqual(got, wantTail) {
		t.Fatalf("argv tail = %v, want %v", got, wantTail)
	}

	// The CertificateFile option must point at the tempfile cleanup path
	// the harness captured (the same one we assert is removed elsewhere).
	if !strings.Contains(strings.Join(harness.observedArgv, " "), "CertificateFile="+harness.observedCertPath) {
		t.Fatalf("argv = %v, want CertificateFile=%q", harness.observedArgv, harness.observedCertPath)
	}
	// The key flag must point at the profile's persistent key, not at a
	// per-invocation key — verifies the engineer-side key reuse alongside
	// the cert mint's PublicKey field check.
	wantKeyPath := filepath.Join(harness.cacheDir, "default", "key")
	keyFlagIdx := -1
	for i, arg := range harness.observedArgv {
		if arg == "-i" {
			keyFlagIdx = i
			break
		}
	}
	if keyFlagIdx < 0 || keyFlagIdx+1 >= len(harness.observedArgv) {
		t.Fatalf("argv = %v, missing -i <key> flag", harness.observedArgv)
	}
	if got := harness.observedArgv[keyFlagIdx+1]; got != wantKeyPath {
		t.Fatalf("argv -i path = %q, want %q", got, wantKeyPath)
	}
}

// TestTimefixAuthFailureNamesLogin mirrors the cert-mint subcommands'
// access-token error wrapping: the engineer should see ErrMintNoAuth plus a
// "run postern --profile <name> login" hint, not a raw token-store error.
func TestTimefixAuthFailureNamesLogin(t *testing.T) {
	tokenErr := errors.New("no token cached")
	rt, harness := newTimefixTestRuntime(t)
	rt.accessToken = func(context.Context, ResolvedProfile) (string, error) {
		return "", tokenErr
	}

	root := rootWithTimefixForTest(rt, nil)
	err := execute(context.Background(), root, "timefix", "device-1234")
	if !errors.Is(err, ErrMintNoAuth) {
		t.Fatalf("Run(timefix) error = %v, want ErrMintNoAuth", err)
	}
	if !errors.Is(err, tokenErr) {
		t.Fatalf("Run(timefix) error = %v, want underlying token error preserved", err)
	}
	if !strings.Contains(err.Error(), `"postern" --profile "default" login`) {
		t.Fatalf("Run(timefix) error = %v, want login hint", err)
	}
	if harness.timefixCalls != 0 {
		t.Fatalf("execSSHTimefix calls = %d, want 0 on auth failure", harness.timefixCalls)
	}
}

// TestTimefixRejectsInvalidDeviceID locks the same device-id validation the
// mint/ssh/scp subcommands apply: path-traversal and bare-dot patterns are
// refused at the CLI boundary before any broker / cert work begins.
func TestTimefixRejectsInvalidDeviceID(t *testing.T) {
	cases := []struct {
		name      string
		device    string
		wantInErr string
	}{
		{"empty", "", "device id is required"},
		{"path-traversal-no-slash", "..", "'..' is not allowed"},
		{"forward-slash", "a/b", "path separators"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt, harness := newTimefixTestRuntime(t)
			rt.profileResolver = func(*cobra.Command) (ResolvedProfile, error) {
				t.Fatal("profile resolver must not be called for an invalid device id")
				return ResolvedProfile{}, nil
			}

			root := rootWithTimefixForTest(rt, nil)
			err := execute(context.Background(), root, "timefix", tc.device)
			if err == nil {
				t.Fatalf("Run(timefix %q) returned nil error", tc.device)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("Run(timefix %q) error = %v, want substring %q", tc.device, err, tc.wantInErr)
			}
			if harness.timefixCalls != 0 {
				t.Fatalf("execSSHTimefix calls = %d, want 0 on invalid device id", harness.timefixCalls)
			}
		})
	}
}

// timefixTestHarness aggregates the in-process broker fakes + the streaming
// exec capture so each test can configure failure modes by setting fields
// without re-wiring closures.
type timefixTestHarness struct {
	ca                   *mintTestCA
	cacheDir             string
	deviceNonce          string
	deviceClock          string
	deviceExitCode       int
	deviceExitErr        error
	jws                  string
	timefixCalls         int
	timePayloadCalls     int
	lastCertRequest      broker.SSHCertIssueRequest
	lastNonceSupplied    string
	lastJWSWritten       string
	observedArgv         []string
	observedCertPath     string
	observedCertContents string
}

func newTimefixTestRuntime(t *testing.T) (runtime, *timefixTestHarness) {
	t.Helper()
	cacheDir := t.TempDir()
	ca := newMintTestCA(t)
	harness := &timefixTestHarness{
		ca:          ca,
		cacheDir:    cacheDir,
		deviceNonce: canonicalTestNonce,
		deviceClock: canonicalTestDeviceClock,
		jws:         "header.payload.signature",
	}

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
		harness.lastCertRequest = request
		return broker.SSHCertIssueResponse{
			SSHCert: marshalCertForTest(t, harness.ca.mintTimefixCert(t, mustParseRequestKey(t, request.PublicKey), request.DeviceID)),
		}, nil
	}
	rt.timePayloadFetch = func(_ context.Context, _ ResolvedProfile, _, _, nonce string) (string, error) {
		harness.timePayloadCalls++
		harness.lastNonceSupplied = nonce
		return harness.jws, nil
	}
	rt.execSSHTimefix = harness.executor()

	return rt, harness
}

// newTimefixTestRuntimeRealBroker is the variant of newTimefixTestRuntime
// that wires the cert-mint seam to a real *broker.SSHCertIssuer rather than
// a fake. Tests that need to exercise the broker's D12 timefix cert-shape
// branch end-to-end pick this constructor; tests that need to inject
// specific cert-mint failure modes stay on the fake-based constructor.
//
// The real issuer runs in-process: SSHCertIssuer.IssueSSHCert is invoked
// directly through the sshCertRequester seam adapter. This skips the HTTP
// transport (the brokerclient call) but exercises every step of the
// broker's cert-mint pipeline including the per-mode cert-shape branch.
func newTimefixTestRuntimeRealBroker(t *testing.T) (runtime, *timefixTestHarness) {
	t.Helper()
	rt, harness := newTimefixTestRuntime(t)

	// Construct a real broker SSHCertIssuer with a fake KMS-equivalent
	// signer (broker.SSHSigner wrapping an in-memory ed25519 key). The
	// rest of the deps are recording stubs from the broker test package
	// — re-declared here as local fakes to keep the test-package
	// boundary clean.
	caSigner := newBrokerTestSigner(t)
	issuer, err := broker.NewSSHCertIssuer(broker.SSHCertIssuerDeps{
		PipelineDeps: broker.PipelineDeps{
			TokenVerifier: fixedBrokerTokenVerifier{claims: broker.EngineerClaims{
				Subject: "test-engineer",
				Email:   "engineer@example.com",
			}},
			Registry:    fixedBrokerRegistry{device: broker.DeviceRecord{Serial: "TESTSERIAL"}},
			Policy:      noopBrokerPolicy{},
			RateLimiter: noopBrokerRateLimiter{},
			Audit:       discardBrokerAudit{},
		},
		Signer: broker.SSHSigner{Signer: caSigner},
	})
	if err != nil {
		t.Fatalf("NewSSHCertIssuer() error = %v", err)
	}

	rt.sshCertRequester = func(ctx context.Context, _ ResolvedProfile, accessToken string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
		harness.lastCertRequest = request
		return issuer.IssueSSHCert(ctx, broker.SSHCertIssueRequest{
			AccessToken:   accessToken,
			DeviceID:      request.DeviceID,
			PrincipalType: request.PrincipalType,
			PublicKey:     request.PublicKey,
		})
	}

	return rt, harness
}

// executor returns a streaming-exec stub that mimics a real timefix-apply
// session: emit the configured nonce + device-clock as the first two
// stdout lines, call the supplier, capture the JWS the runtime writes to
// "stdin", return the configured exit code. The captured cert path comes
// off the -o CertificateFile= argv entry so cleanup assertions can stat
// the file post-call; the cert contents are read while the file still
// exists so tests can introspect the broker-issued cert without racing
// the deferred cleanup.
func (h *timefixTestHarness) executor() execSSHTimefixFunc {
	return func(_ context.Context, argv []string, supplier jwsSupplierFunc, _ io.Writer) (int, error) {
		h.timefixCalls++
		argvCopy := append([]string(nil), argv...)
		h.observedArgv = argvCopy
		h.observedCertPath = extractCertPath(argvCopy)

		if h.observedCertPath != "" {
			if contents, err := os.ReadFile(h.observedCertPath); err == nil {
				h.observedCertContents = string(contents)
			}
		}

		jws, err := supplier(h.deviceNonce, h.deviceClock)
		if err != nil {
			return 0, err
		}
		h.lastJWSWritten = jws

		return h.deviceExitCode, h.deviceExitErr
	}
}

// extractCertPath pulls the CertificateFile= argv value (without the prefix)
// so the harness can stat-then-not-exist after the call.
func extractCertPath(argv []string) string {
	const prefix = "CertificateFile="
	for _, arg := range argv {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix)
		}
	}
	return ""
}

// mintTimefixCert mints an SSH cert whose principal matches the timefix
// shape (device-<id>-timefix). The broker would produce a cert valid 1970
// → 3000; tests don't need to assert on the validity window here, only on
// the request side, so any plausible duration works.
func (ca *mintTestCA) mintTimefixCert(t *testing.T, subject ssh.PublicKey, deviceID string) *ssh.Certificate {
	t.Helper()
	cert := &ssh.Certificate{
		Key:             subject,
		Serial:          atomic.AddUint64(&timefixCertSerial, 1),
		CertType:        ssh.UserCert,
		KeyId:           "device-" + deviceID + "-timefix",
		ValidPrincipals: []string{"device-" + deviceID + "-timefix"},
		ValidAfter:      0,
		ValidBefore:     uint64(time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca.signer); err != nil {
		t.Fatalf("SignCert() error = %v", err)
	}
	return cert
}

// timefixCertSerial provides distinct serials across mintTimefixCert calls
// so cert-on-disk comparisons in repeated invocations don't accidentally
// match by collision.
var timefixCertSerial uint64

// rootWithTimefixForTest assembles a minimal cobra root carrying just the
// timefix subcommand. Mirrors the rootWith*ForTest helpers in sibling test
// files.
func rootWithTimefixForTest(rt runtime, stdout *bytes.Buffer) *cobra.Command {
	root := &cobra.Command{Use: DefaultBinaryName, SilenceUsage: true, SilenceErrors: true}
	if stdout != nil {
		root.SetOut(stdout)
	}
	root.PersistentFlags().String(ProfileFlagName, "", "config profile")
	root.AddCommand(timefixCommand(rt))
	return root
}

// Broker test fakes for the real-pipeline runtime variant. These mirror
// the same shape internal/broker's own test suite uses but live in the
// cliapp test package so the timefix tests can construct a real
// SSHCertIssuer without a cross-package internal-test import.

func newBrokerTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}
	return signer
}

type fixedBrokerTokenVerifier struct {
	claims broker.EngineerClaims
	err    error
}

func (v fixedBrokerTokenVerifier) VerifyAccessToken(context.Context, string) (broker.EngineerClaims, error) {
	return v.claims, v.err
}

type fixedBrokerRegistry struct {
	device broker.DeviceRecord
	err    error
}

func (r fixedBrokerRegistry) ResolveDevice(context.Context, string) (broker.DeviceRecord, error) {
	return r.device, r.err
}

type noopBrokerPolicy struct{}

func (noopBrokerPolicy) Allow(context.Context, broker.PolicyRequest) error { return nil }

type noopBrokerRateLimiter struct{}

func (noopBrokerRateLimiter) Allow(context.Context, broker.RateLimitRequest) error { return nil }

type discardBrokerAudit struct{}

func (discardBrokerAudit) Record(context.Context, broker.AuditEvent) error { return nil }
