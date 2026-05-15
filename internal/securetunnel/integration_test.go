package securetunnel

// Cross-package integration test for the tunneling phase. Wires:
//
//   brokerclient (HTTP client)  →
//   httptest.Server hosting brokerhandlers.New(Deps{...})  →
//   real *broker.TunnelIssuer (with the LD-93 SRP-split pipeline)  →
//   fake broker.Tunneling that returns a SourceAccessToken pointing at  →
//   the in-process fakeV3Server (V3 WebSocket fake from fake_test.go)  →
//   StartSourceProxy (real, dial-URL-overridden at the test seam)  →
//   loopback TCP listener bound by the proxy  →
//   echo "device" reachable via the fake's per-stream echo behavior.
//
// The unit tests in TN-A..F cover each piece in isolation; this test
// proves the seams between them connect end-to-end without exposing any
// new package surface. The dialURLOverride / httpClient test seams on
// SourceProxyOptions are package-private, so the test lives in package
// securetunnel rather than an external location — every other package
// it touches is consumed via public imports.
//
// Per LD-65 (audit-coverage strict invariant) and §8 success criterion 3:
// the happy path emits tunnel_authorized + tunnel_issued events joined
// on JTI, both routed through the real broker pipeline.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"go.uber.org/goleak"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/internal/brokerclient"
	"github.com/atomicgravity/postern/pkg/brokerhandlers"
)

// TestTunnelingEndToEnd_HappyPath drives the full firewalled-device path
// through every layer the production code uses:
//
//  1. brokerclient.Client.OpenTunnel calls a real brokerhandlers.New()
//     HTTP handler over httptest's loopback transport.
//  2. The handler routes to a real *broker.TunnelIssuer with real
//     pipeline preambles (TokenVerify + RateLimit + Registry + Policy).
//  3. The fake broker.Tunneling returns a {tunnel_id, source_access_token,
//     region} triple pointing at the in-process V3 WebSocket fake.
//  4. The CLI-side path: StartSourceProxy dials the V3 fake's WebSocket,
//     completes the SERVICE_IDS handshake, and binds a loopback TCP
//     listener.
//  5. A TCP client writes bytes to the loopback listener; the fake's
//     per-stream echo bounces them back; the client reads them out
//     unchanged.
//
// Audit + clean-teardown invariants asserted at the end.
func TestTunnelingEndToEnd_HappyPath(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	// V3 WebSocket fake stands in for the AWS tunneling data plane.
	// The fake's echoStreams default bounces incoming DATA frames back
	// on the same stream id.
	fake := newFakeV3Server(t)

	// Fake Tunneling abstraction returns the canned source-side token
	// the fake validates on its WebSocket handshake. Region is required
	// by the source proxy's options validation but is unused in the
	// test path because dialURLOverride bypasses URL construction.
	tunneling := &integrationFakeTunneling{
		result: broker.TunnelOpenResult{
			TunnelID:          "tun-integration-abc",
			SourceAccessToken: "test-source-token",
			Region:            "us-east-1",
		},
	}

	// Real *broker.TunnelIssuer wired with the same pipeline deps the
	// production wiring uses, minus the Signer (tunneling doesn't sign
	// anything).
	auditRecorder := &integrationAudit{}
	issuer, err := broker.NewTunnelIssuer(broker.TunnelIssuerDeps{
		PipelineDeps: broker.PipelineDeps{
			TokenVerifier: integrationTokenVerifier{claims: broker.EngineerClaims{
				Subject: "engineer-42",
				Email:   "engineer@example.com",
				Groups:  []string{"postern-engineers"},
			}},
			Registry: integrationRegistry{record: broker.DeviceRecord{
				Serial:     "S1234",
				FriendlyID: "device-1234",
			}},
			Policy:      integrationPolicy{},
			RateLimiter: integrationRateLimiter{},
			Audit:       auditRecorder,
		},
		Tunneling:                 tunneling,
		DefaultMaxLifetimeMinutes: 480,
	})
	if err != nil {
		t.Fatalf("NewTunnelIssuer() error = %v", err)
	}

	// SSHCertIssuer + TimePayloadIssuer fields are nil; this test only
	// exercises /ssh/tunnel. brokerhandlers.New tolerates nil siblings
	// (those endpoints return 501 if hit) but /healthz fails when no
	// SSHCertIssuer is wired — we never hit /healthz, so the integration
	// path tolerates that nil too.
	brokerHandler := brokerhandlers.New(brokerhandlers.Deps{
		SSHCertIssuer: integrationCertIssuerStub{},
		TunnelIssuer:  issuer,
	})
	brokerServer := httptest.NewServer(brokerHandler)
	t.Cleanup(brokerServer.Close)

	// brokerclient.OpenTunnel hits the in-process broker over real HTTP.
	// The response carries the tunneling fake's canned source-side token,
	// which the source-proxy step below presents to the WebSocket fake.
	client := brokerclient.New(brokerServer.URL, nil)
	tunnelResponse, err := client.OpenTunnel(context.Background(), "engineer-access-token", "device-1234", 0)
	if err != nil {
		t.Fatalf("brokerclient.OpenTunnel() error = %v", err)
	}
	if tunnelResponse.TunnelID != "tun-integration-abc" {
		t.Fatalf("TunnelID = %q, want %q", tunnelResponse.TunnelID, "tun-integration-abc")
	}
	if tunnelResponse.SourceAccessToken != "test-source-token" {
		t.Fatalf("SourceAccessToken (broker response) did not match the canned fake token")
	}

	// Audit invariant: by this point, two events should have landed
	// (authorized + issued), joined on the same JTI. This is the LD-65
	// strict-coverage invariant — proving the integration path doesn't
	// short-circuit either emit.
	if got, want := auditRecorder.eventCount(), 2; got != want {
		t.Fatalf("audit event count after broker call = %d, want %d (authorized+issued)", got, want)
	}
	events := auditRecorder.snapshot()
	if events[0].Event != broker.EventTunnelAuthorized {
		t.Fatalf("first audit event = %q, want %q", events[0].Event, broker.EventTunnelAuthorized)
	}
	if events[1].Event != broker.EventTunnelIssued {
		t.Fatalf("second audit event = %q, want %q", events[1].Event, broker.EventTunnelIssued)
	}
	if events[0].JTI == "" || events[0].JTI != events[1].JTI {
		t.Fatalf("audit JTIs must match and be non-empty; authorized=%q issued=%q", events[0].JTI, events[1].JTI)
	}

	// Now drive the CLI-side source-proxy path. The dialURLOverride
	// + httpClient seams are the same ones unit tests use; this is the
	// same dial path production code runs except for the fake URL.
	proxy, err := StartSourceProxy(context.Background(), SourceProxyOptions{
		Region:            tunnelResponse.Region,
		SourceAccessToken: tunnelResponse.SourceAccessToken,
		dialURLOverride:   fake.URL(),
		httpClient:        fake.httpClient(),
	})
	if err != nil {
		t.Fatalf("StartSourceProxy() error = %v", err)
	}
	defer func() {
		_ = proxy.Close()
		_ = proxy.Wait()
	}()

	if proxy.LocalPort() == 0 {
		t.Fatal("LocalPort = 0; listener did not bind")
	}

	// Connect a TCP client to the proxy's loopback listener and round-
	// trip bytes through the full stack. The proxy emits STREAM_START
	// on accept, forwards client bytes as DATA frames, and the fake's
	// per-stream echo bounces them back on the same stream-id.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxy.LocalPort()))
	if err != nil {
		t.Fatalf("dial local proxy: %v", err)
	}
	defer conn.Close()

	payload := []byte("postern tunneling integration round-trip")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload to proxy: %v", err)
	}

	got, err := drainConn(conn, len(payload))
	if err != nil {
		t.Fatalf("read echoed payload: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, payload)
	}

	// Source access token invariant T: never logged, never persisted.
	// The broker's audit events MUST NOT carry the source access token
	// in any field — the integration recorder captures all event fields
	// so a leak would show up here.
	for _, ev := range auditRecorder.snapshot() {
		blob, _ := json.Marshal(ev)
		if strings.Contains(string(blob), tunneling.result.SourceAccessToken) {
			t.Fatalf("source access token leaked into audit event: %s", blob)
		}
	}
}

// integrationFakeTunneling is the fake broker.Tunneling impl used by the
// integration test. The fake returns a canned TunnelOpenResult; the test
// arranges for the SourceAccessToken to match the fakeV3Server's
// expectedToken so the WebSocket handshake succeeds.
type integrationFakeTunneling struct {
	mu     sync.Mutex
	calls  int
	last   broker.TunnelOpenInternal
	result broker.TunnelOpenResult
}

func (t *integrationFakeTunneling) OpenTunnel(_ context.Context, request broker.TunnelOpenInternal) (broker.TunnelOpenResult, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.calls++
	t.last = request
	return t.result, nil
}

// integrationTokenVerifier accepts any access token and returns canned
// EngineerClaims. The broker pipeline only consults VerifyAccessToken's
// return value; the token bytes themselves don't propagate beyond
// preamble.
type integrationTokenVerifier struct {
	claims broker.EngineerClaims
}

func (v integrationTokenVerifier) VerifyAccessToken(context.Context, string) (broker.EngineerClaims, error) {
	return v.claims, nil
}

// integrationRegistry returns a fixed DeviceRecord on every lookup.
type integrationRegistry struct {
	record broker.DeviceRecord
}

func (r integrationRegistry) ResolveDevice(context.Context, string) (broker.DeviceRecord, error) {
	return r.record, nil
}

// integrationPolicy admits every request — the integration test focuses
// on the wire-shape seams, not policy evaluation. A real AVPPolicy would
// run via IsAuthorizedWithToken; that's already covered by the AVPPolicy
// unit tests.
type integrationPolicy struct{}

func (integrationPolicy) Allow(context.Context, broker.PolicyRequest) error {
	return nil
}

// integrationRateLimiter admits every request. RateLimiter unit tests
// cover the DynamoDB-backed budget shape.
type integrationRateLimiter struct{}

func (integrationRateLimiter) Allow(context.Context, broker.RateLimitRequest) error {
	return nil
}

// integrationAudit is the AuditSink used by the integration test. It
// captures every recorded event under a mutex so the test can assert on
// the full sequence post-round-trip; matches the recordingAudit shape
// the in-package broker tests use.
type integrationAudit struct {
	mu     sync.Mutex
	events []broker.AuditEvent
}

func (a *integrationAudit) Record(_ context.Context, event broker.AuditEvent) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, event)
	return nil
}

func (a *integrationAudit) eventCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.events)
}

func (a *integrationAudit) snapshot() []broker.AuditEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]broker.AuditEvent, len(a.events))
	copy(out, a.events)
	return out
}

// integrationCertIssuerStub satisfies the SSHCertIssuer interface so the
// brokerhandlers wiring's /healthz check (which surfaces 503 when no
// SSHCertIssuer is supplied) doesn't trip on a nil. The integration
// test never hits /ssh/cert.
type integrationCertIssuerStub struct{}

func (integrationCertIssuerStub) IssueSSHCert(context.Context, broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
	return broker.SSHCertIssueResponse{}, broker.Error{StatusCode: http.StatusNotImplemented, Message: "not used in this test"}
}

func (integrationCertIssuerStub) RecordSSHCertHandlerDenial(context.Context, broker.HandlerDenial) {
}

// Compile-time assertion that integrationCertIssuerStub matches the
// pkg/brokerhandlers.SSHCertIssuer interface shape; if the broker
// interface drifts, the test surfaces a build error rather than a
// runtime nil-method-set panic.
var _ brokerhandlers.SSHCertIssuer = integrationCertIssuerStub{}
