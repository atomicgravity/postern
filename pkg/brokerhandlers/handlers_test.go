package brokerhandlers

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/realclientip/realclientip-go"
)

func TestHealthzReturnsOK(t *testing.T) {
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}})
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got, want := response.Body.String(), "ok\n"; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// TestHealthzReturnsUnavailableWhenIssuerNil locks F-BROKER-6: when the
// wrapping forgets to inject SSHCertIssuer, /healthz must fail the load
// balancer's check rather than returning 200 alongside /ssh/cert's 501.
func TestHealthzReturnsUnavailableWhenIssuerNil(t *testing.T) {
	handler := New(Deps{})
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

// TestMethodMismatchReturns405WithAllow locks the contract that ServeMux's
// method-prefixed patterns handle 405 + Allow themselves; individual
// handlers should never see a wrong-method request and should not re-check.
func TestMethodMismatchReturns405WithAllow(t *testing.T) {
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}})
	cases := []struct {
		path      string
		method    string
		wantAllow string
	}{
		{"/healthz", http.MethodPost, "GET, HEAD"},
		{"/ssh/cert", http.MethodDelete, "POST"},
	}
	cases = append(cases, struct {
		path      string
		method    string
		wantAllow string
	}{"/ssh/time-payload", http.MethodGet, "POST"})
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if got, want := response.Code, http.StatusMethodNotAllowed; got != want {
				t.Fatalf("status = %d, want %d", got, want)
			}
			if got := response.Header().Get("Allow"); got != tc.wantAllow {
				t.Fatalf("Allow header = %q, want %q", got, tc.wantAllow)
			}
		})
	}
}

func TestHealthzReturnsUnavailableWhenCheckerFails(t *testing.T) {
	handler := New(Deps{
		SSHCertIssuer: &recordingSSHCertIssuer{},
		HealthChecker: failingHealthChecker{err: errors.New("down")},
	})
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func TestSSHCertIssuesOperatorCert(t *testing.T) {
	issuer := &recordingSSHCertIssuer{
		response: broker.SSHCertIssueResponse{
			SSHCert:             "ssh-ed25519-cert-v01@openssh.com AAAA...",
			CAPubkeyFingerprint: "SHA256:abc123",
		},
	}
	handler := New(Deps{SSHCertIssuer: issuer})
	request := httptest.NewRequest(http.MethodPost, "/ssh/cert", strings.NewReader(`{"device_id":"device-123","principal_type":"operator","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"}`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	request.Header.Set("User-Agent", "postern/test")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got, want := issuer.request.AccessToken, "access-token-123"; got != want {
		t.Fatalf("access token = %q, want %q", got, want)
	}
	if got, want := issuer.request.DeviceID, "device-123"; got != want {
		t.Fatalf("device id = %q, want %q", got, want)
	}
	if got, want := issuer.request.PrincipalType, broker.PrincipalTypeOperator; got != want {
		t.Fatalf("principal type = %q, want %q", got, want)
	}
	if got, want := issuer.request.PublicKey, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"; got != want {
		t.Fatalf("public key = %q, want %q", got, want)
	}
	if got, want := issuer.request.UserAgent, "postern/test"; got != want {
		t.Fatalf("user agent = %q, want %q", got, want)
	}

	var body broker.SSHCertIssueResponse
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got, want := body.SSHCert, "ssh-ed25519-cert-v01@openssh.com AAAA..."; got != want {
		t.Fatalf("ssh_cert = %q, want %q", got, want)
	}
}

// TestSSHCertRequiresBearerToken locks both the wire-format reject (401
// without an Authorization header) AND the audit-coverage invariant: a
// pre-invocation deny audit is emitted with reason `missing_bearer_token`
// so operators see every probe of /ssh/cert that lacked credentials.
func TestSSHCertRequiresBearerToken(t *testing.T) {
	issuer := &recordingSSHCertIssuer{}
	handler := New(Deps{SSHCertIssuer: issuer})
	request := httptest.NewRequest(http.MethodPost, "/ssh/cert", strings.NewReader(`{"device_id":"device-123","principal_type":"operator","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"}`))
	request.Header.Set("User-Agent", "postern/test")
	request.RemoteAddr = "203.0.113.1:12345"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got, want := issuer.issueCalls, 0; got != want {
		t.Fatalf("IssueSSHCert calls = %d, want %d (must not be reached without a bearer token)", got, want)
	}
	if got, want := len(issuer.handlerDenials), 1; got != want {
		t.Fatalf("handler denials = %d, want %d", got, want)
	}
	denial := issuer.handlerDenials[0]
	if denial.DeniedReason != broker.DenyReasonMissingBearerToken {
		t.Fatalf("denied_reason = %q, want %q", denial.DeniedReason, broker.DenyReasonMissingBearerToken)
	}
	if denial.UserAgent != "postern/test" {
		t.Fatalf("user_agent = %q, want %q", denial.UserAgent, "postern/test")
	}
	if denial.SourceIP != "203.0.113.1" {
		t.Fatalf("source_ip = %q, want %q (port should be stripped)", denial.SourceIP, "203.0.113.1")
	}
}

// TestSSHCertAuditsMalformedRequestBody locks the second pre-invocation
// audit path: malformed JSON body produces a 400 plus a deny audit with
// reason `malformed_request_body`. Without this, an attacker could probe
// the broker with garbage bodies and leave no trace.
func TestSSHCertAuditsMalformedRequestBody(t *testing.T) {
	issuer := &recordingSSHCertIssuer{}
	handler := New(Deps{SSHCertIssuer: issuer})
	request := httptest.NewRequest(http.MethodPost, "/ssh/cert", strings.NewReader(`{this is not valid json`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	request.Header.Set("User-Agent", "postern/test")
	request.RemoteAddr = "203.0.113.1:12345"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusBadRequest; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got, want := issuer.issueCalls, 0; got != want {
		t.Fatalf("IssueSSHCert calls = %d, want %d", got, want)
	}
	if got, want := len(issuer.handlerDenials), 1; got != want {
		t.Fatalf("handler denials = %d, want %d", got, want)
	}
	if got, want := issuer.handlerDenials[0].DeniedReason, broker.DenyReasonMalformedRequestBody; got != want {
		t.Fatalf("denied_reason = %q, want %q", got, want)
	}
}

func TestSSHCertReturnsNotImplementedWithoutIssuer(t *testing.T) {
	handler := New(Deps{})
	request := httptest.NewRequest(http.MethodPost, "/ssh/cert", strings.NewReader(`{"device_id":"device-123","principal_type":"operator","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"}`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusNotImplemented; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

func TestSSHCertTranslatesDomainErrorToHTTPStatus(t *testing.T) {
	// broker.Error from the issuer must surface as the requested HTTP
	// status. Regression guard: errors.As path in writeIssueError.
	issuer := &recordingSSHCertIssuer{err: broker.Error{StatusCode: http.StatusForbidden, Message: "denied"}}
	handler := New(Deps{SSHCertIssuer: issuer})
	request := httptest.NewRequest(http.MethodPost, "/ssh/cert", strings.NewReader(`{"device_id":"device-123","principal_type":"operator","public_key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey"}`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusForbidden; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
}

// TestSSHCertSourceIPDirectDeploy locks the default direct-deploy behavior:
// no ClientIPStrategy configured means body.RemoteAddr is the connecting
// socket address with the port stripped, regardless of any X-Forwarded-For
// header on the request. Operators behind a trusted proxy must opt in via
// trusted_proxies for XFF parsing to apply.
func TestSSHCertSourceIPDirectDeploy(t *testing.T) {
	issuer := &recordingSSHCertIssuer{
		response: broker.SSHCertIssueResponse{SSHCert: "ssh-ed25519-cert-v01@openssh.com AAAA...", CAPubkeyFingerprint: "SHA256:abc"},
	}
	handler := New(Deps{SSHCertIssuer: issuer})

	request := httptest.NewRequest(http.MethodPost, "/ssh/cert", strings.NewReader(`{"device_id":"device-123","principal_type":"operator","public_key":"ssh-ed25519 AAAA"}`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	request.Header.Set("X-Forwarded-For", "198.51.100.7, 192.0.2.1")
	request.RemoteAddr = "203.0.113.5:54321"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got, want := issuer.request.RemoteAddr, "203.0.113.5"; got != want {
		t.Fatalf("RemoteAddr = %q, want %q", got, want)
	}
}

// TestSSHCertSourceIPBehindTrustedProxy confirms the strategy hooks together:
// when the operator wires a rightmost-trusted-range strategy, body.RemoteAddr
// becomes the rightmost XFF entry that's not inside the trusted CIDRs — i.e.,
// the engineer's IP, not the LB's. Algorithm correctness is the library's
// responsibility; this test confirms the wiring.
func TestSSHCertSourceIPBehindTrustedProxy(t *testing.T) {
	_, trusted, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR() error = %v", err)
	}
	rightmost, err := realclientip.NewRightmostTrustedRangeStrategy("X-Forwarded-For", []net.IPNet{*trusted})
	if err != nil {
		t.Fatalf("NewRightmostTrustedRangeStrategy() error = %v", err)
	}
	strategy := realclientip.NewChainStrategy(rightmost, realclientip.RemoteAddrStrategy{})

	issuer := &recordingSSHCertIssuer{
		response: broker.SSHCertIssueResponse{SSHCert: "ssh-ed25519-cert-v01@openssh.com AAAA...", CAPubkeyFingerprint: "SHA256:abc"},
	}
	handler := New(Deps{SSHCertIssuer: issuer, ClientIPStrategy: strategy})

	request := httptest.NewRequest(http.MethodPost, "/ssh/cert", strings.NewReader(`{"device_id":"device-123","principal_type":"operator","public_key":"ssh-ed25519 AAAA"}`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	request.Header.Set("X-Forwarded-For", "198.51.100.7, 192.0.2.1")
	request.RemoteAddr = "192.0.2.10:54321"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got, want := issuer.request.RemoteAddr, "198.51.100.7"; got != want {
		t.Fatalf("RemoteAddr = %q, want %q", got, want)
	}
}

// TestTimePayloadIssuesAndPassesParsedFields locks the happy-path handler
// wiring: bearer + JSON body decode → IssueTimePayload → JSON response
// carrying time_payload + jti. Verifies that DeviceID + Nonce are
// normalized (trimmed) before dispatch and the bearer token flows into
// the broker-domain request as AccessToken.
func TestTimePayloadIssuesAndPassesParsedFields(t *testing.T) {
	issuer := &recordingTimePayloadIssuer{
		response: broker.TimePayloadIssueResponse{TimePayload: "header.payload.signature", JTI: "01969cc1"},
	}
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}, TimePayloadIssuer: issuer})
	body := `{"device_id":"  prod-a012  ","nonce":"  AAAA  "}`
	request := httptest.NewRequest(http.MethodPost, "/ssh/time-payload", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer access-token-123")
	request.Header.Set("User-Agent", "postern/test")
	request.RemoteAddr = "203.0.113.1:12345"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got, want := issuer.issueCalls, 1; got != want {
		t.Fatalf("IssueTimePayload calls = %d, want %d", got, want)
	}
	if got, want := issuer.request.AccessToken, "access-token-123"; got != want {
		t.Fatalf("AccessToken = %q, want %q", got, want)
	}
	if got, want := issuer.request.DeviceID, "prod-a012"; got != want {
		t.Fatalf("DeviceID = %q, want %q (must be trimmed)", got, want)
	}
	if got, want := issuer.request.Nonce, "AAAA"; got != want {
		t.Fatalf("Nonce = %q, want %q (must be trimmed)", got, want)
	}
	if got, want := issuer.request.UserAgent, "postern/test"; got != want {
		t.Fatalf("UserAgent = %q, want %q", got, want)
	}
	if got, want := issuer.request.RemoteAddr, "203.0.113.1"; got != want {
		t.Fatalf("RemoteAddr = %q, want %q (port stripped)", got, want)
	}

	var decoded broker.TimePayloadIssueResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got, want := decoded.TimePayload, "header.payload.signature"; got != want {
		t.Fatalf("time_payload = %q, want %q", got, want)
	}
	if got, want := decoded.JTI, "01969cc1"; got != want {
		t.Fatalf("jti = %q, want %q", got, want)
	}
}

// TestTimePayloadRequiresBearerToken locks both the 401 reject AND the
// audit-coverage invariant for /ssh/time-payload: a pre-invocation deny
// audit (time_payload_denied) is emitted with reason missing_bearer_token
// so operators see every probe of /ssh/time-payload that lacked
// credentials.
func TestTimePayloadRequiresBearerToken(t *testing.T) {
	certIssuer := &recordingSSHCertIssuer{}
	issuer := &recordingTimePayloadIssuer{}
	handler := New(Deps{SSHCertIssuer: certIssuer, TimePayloadIssuer: issuer})
	request := httptest.NewRequest(http.MethodPost, "/ssh/time-payload", strings.NewReader(`{"device_id":"d","nonce":"n"}`))
	request.Header.Set("User-Agent", "postern/test")
	request.RemoteAddr = "203.0.113.1:12345"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got, want := issuer.issueCalls, 0; got != want {
		t.Fatalf("IssueTimePayload calls = %d, want %d", got, want)
	}
	if got, want := len(issuer.handlerDenials), 1; got != want {
		t.Fatalf("time-payload handler denials = %d, want %d", got, want)
	}
	if got, want := issuer.handlerDenials[0].DeniedReason, broker.DenyReasonMissingBearerToken; got != want {
		t.Fatalf("denied_reason = %q, want %q", got, want)
	}
	// Cross-endpoint isolation: the /ssh/cert handler-denial slice
	// stays empty so operators filtering by event type get clean
	// per-endpoint counts.
	if got, want := len(certIssuer.handlerDenials), 0; got != want {
		t.Fatalf("ssh_cert handler denials leaked = %d, want %d", got, want)
	}
}

// TestTimePayloadAuditsMalformedRequestBody locks the second pre-invocation
// audit path: invalid JSON or unknown fields produce a 400 plus a
// time_payload_denied audit with reason malformed_request_body.
func TestTimePayloadAuditsMalformedRequestBody(t *testing.T) {
	issuer := &recordingTimePayloadIssuer{}
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}, TimePayloadIssuer: issuer})
	cases := []struct {
		name string
		body string
	}{
		{"invalid JSON", `{not json`},
		{"unknown field rejected by DisallowUnknownFields", `{"device_id":"d","nonce":"n","extra":"field"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer.handlerDenials = nil
			issuer.issueCalls = 0
			request := httptest.NewRequest(http.MethodPost, "/ssh/time-payload", strings.NewReader(tc.body))
			request.Header.Set("Authorization", "Bearer access-token-123")
			request.RemoteAddr = "203.0.113.1:12345"
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if got, want := response.Code, http.StatusBadRequest; got != want {
				t.Fatalf("status = %d, want %d", got, want)
			}
			if issuer.issueCalls != 0 {
				t.Fatalf("IssueTimePayload calls = %d, want 0", issuer.issueCalls)
			}
			if len(issuer.handlerDenials) != 1 {
				t.Fatalf("denials = %d, want 1", len(issuer.handlerDenials))
			}
			if got, want := issuer.handlerDenials[0].DeniedReason, broker.DenyReasonMalformedRequestBody; got != want {
				t.Fatalf("denied_reason = %q, want %q", got, want)
			}
		})
	}
}

// TestTimePayloadReturnsNotImplementedWithoutIssuer locks the wrapping-
// misconfiguration signal: no issuer wired → 501 (parallel to handleSSHCert).
func TestTimePayloadReturnsNotImplementedWithoutIssuer(t *testing.T) {
	handler := New(Deps{})
	request := httptest.NewRequest(http.MethodPost, "/ssh/time-payload", strings.NewReader(`{"device_id":"d","nonce":"n"}`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusNotImplemented; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

// TestTimePayloadTranslatesDomainErrorToHTTPStatus confirms broker.Error
// from the time-payload pipeline surfaces with its StatusCode (writeIssue
// Error is shared with handleSSHCert).
func TestTimePayloadTranslatesDomainErrorToHTTPStatus(t *testing.T) {
	issuer := &recordingTimePayloadIssuer{err: broker.Error{StatusCode: http.StatusForbidden, Message: "denied"}}
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}, TimePayloadIssuer: issuer})
	request := httptest.NewRequest(http.MethodPost, "/ssh/time-payload", strings.NewReader(`{"device_id":"d","nonce":"n"}`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusForbidden; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
}

// TestTunnelOpensAndPassesParsedFields locks the happy-path handler wiring
// for /ssh/tunnel: bearer + JSON body decode → OpenTunnel → JSON response
// carrying the AWS-side tunnel triple. Verifies DeviceID is trimmed before
// dispatch and the engineer-requested max_lifetime flows through.
func TestTunnelOpensAndPassesParsedFields(t *testing.T) {
	issuer := &recordingTunnelIssuer{
		response: broker.TunnelOpenResponse{
			TunnelID:           "tun-abc",
			SourceAccessToken:  "source-token",
			Region:             "us-west-2",
			MaxLifetimeMinutes: 240,
		},
	}
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}, TunnelIssuer: issuer})
	body := `{"device_id":"  prod-a012  ","max_lifetime_minutes":240}`
	request := httptest.NewRequest(http.MethodPost, "/ssh/tunnel", strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer access-token-123")
	request.Header.Set("User-Agent", "postern/test")
	request.RemoteAddr = "203.0.113.1:12345"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusOK; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
	if got, want := issuer.issueCalls, 1; got != want {
		t.Fatalf("OpenTunnel calls = %d, want %d", got, want)
	}
	if got, want := issuer.request.AccessToken, "access-token-123"; got != want {
		t.Fatalf("AccessToken = %q, want %q", got, want)
	}
	if got, want := issuer.request.DeviceID, "prod-a012"; got != want {
		t.Fatalf("DeviceID = %q, want %q (must be trimmed)", got, want)
	}
	if got, want := issuer.request.MaxLifetimeMinutes, int32(240); got != want {
		t.Fatalf("MaxLifetimeMinutes = %d, want %d", got, want)
	}
	if got, want := issuer.request.RemoteAddr, "203.0.113.1"; got != want {
		t.Fatalf("RemoteAddr = %q, want %q (port stripped)", got, want)
	}

	var decoded broker.TunnelOpenResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if got, want := decoded.TunnelID, "tun-abc"; got != want {
		t.Fatalf("tunnel_id = %q, want %q", got, want)
	}
	if got, want := decoded.SourceAccessToken, "source-token"; got != want {
		t.Fatalf("source_access_token = %q, want %q", got, want)
	}
	if got, want := decoded.Region, "us-west-2"; got != want {
		t.Fatalf("region = %q, want %q", got, want)
	}
	if got, want := decoded.MaxLifetimeMinutes, int32(240); got != want {
		t.Fatalf("max_lifetime_minutes = %d, want %d", got, want)
	}
}

// TestTunnelRejectsNonPOSTMethods locks the method-prefixed route: GET /
// DELETE / etc. against /ssh/tunnel return 405 with the Allow header
// listing POST. Closes F-BRK-M3 — the prior 501 stub accepted any verb.
func TestTunnelRejectsNonPOSTMethods(t *testing.T) {
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}, TunnelIssuer: &recordingTunnelIssuer{}})
	for _, method := range []string{http.MethodGet, http.MethodDelete, http.MethodPut, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			request := httptest.NewRequest(method, "/ssh/tunnel", nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if got, want := response.Code, http.StatusMethodNotAllowed; got != want {
				t.Fatalf("status = %d, want %d", got, want)
			}
			if got, want := response.Header().Get("Allow"), "POST"; got != want {
				t.Fatalf("Allow header = %q, want %q", got, want)
			}
		})
	}
}

// TestTunnelRequiresBearerToken locks both the 401 reject AND the audit
// coverage: a pre-invocation tunnel_denied audit emits with reason
// missing_bearer_token.
func TestTunnelRequiresBearerToken(t *testing.T) {
	issuer := &recordingTunnelIssuer{}
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}, TunnelIssuer: issuer})
	request := httptest.NewRequest(http.MethodPost, "/ssh/tunnel", strings.NewReader(`{"device_id":"d"}`))
	request.Header.Set("User-Agent", "postern/test")
	request.RemoteAddr = "203.0.113.1:12345"
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusUnauthorized; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
	if got, want := issuer.issueCalls, 0; got != want {
		t.Fatalf("OpenTunnel calls = %d, want %d", got, want)
	}
	if got, want := len(issuer.handlerDenials), 1; got != want {
		t.Fatalf("tunnel handler denials = %d, want %d", got, want)
	}
	if got, want := issuer.handlerDenials[0].DeniedReason, broker.DenyReasonMissingBearerToken; got != want {
		t.Fatalf("denied_reason = %q, want %q", got, want)
	}
}

// TestTunnelAuditsMalformedRequestBody locks the second pre-invocation
// audit path: invalid JSON / unknown fields → 400 + tunnel_denied with
// reason malformed_request_body.
func TestTunnelAuditsMalformedRequestBody(t *testing.T) {
	issuer := &recordingTunnelIssuer{}
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}, TunnelIssuer: issuer})
	cases := []struct {
		name string
		body string
	}{
		{"invalid JSON", `{not json`},
		{"unknown field rejected by DisallowUnknownFields", `{"device_id":"d","extra":"field"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer.handlerDenials = nil
			issuer.issueCalls = 0
			request := httptest.NewRequest(http.MethodPost, "/ssh/tunnel", strings.NewReader(tc.body))
			request.Header.Set("Authorization", "Bearer access-token-123")
			request.RemoteAddr = "203.0.113.1:12345"
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if got, want := response.Code, http.StatusBadRequest; got != want {
				t.Fatalf("status = %d, want %d", got, want)
			}
			if issuer.issueCalls != 0 {
				t.Fatalf("OpenTunnel calls = %d, want 0", issuer.issueCalls)
			}
			if len(issuer.handlerDenials) != 1 {
				t.Fatalf("denials = %d, want 1", len(issuer.handlerDenials))
			}
			if got, want := issuer.handlerDenials[0].DeniedReason, broker.DenyReasonMalformedRequestBody; got != want {
				t.Fatalf("denied_reason = %q, want %q", got, want)
			}
		})
	}
}

// TestTunnelReturnsNotImplementedWithoutIssuer locks the wrapping-
// misconfig signal: no TunnelIssuer wired → 501. Parallels the other
// handlers; the unwrapped broker without a tunneling YAML section
// exercises this path.
func TestTunnelReturnsNotImplementedWithoutIssuer(t *testing.T) {
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}})
	request := httptest.NewRequest(http.MethodPost, "/ssh/tunnel", strings.NewReader(`{"device_id":"d"}`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusNotImplemented; got != want {
		t.Fatalf("status = %d, want %d", got, want)
	}
}

// TestTunnelTranslatesDomainErrorToHTTPStatus confirms broker.Error from
// the tunnel pipeline surfaces with its StatusCode — the same
// writeIssueError used by the cert + time-payload handlers.
func TestTunnelTranslatesDomainErrorToHTTPStatus(t *testing.T) {
	issuer := &recordingTunnelIssuer{err: broker.Error{StatusCode: http.StatusServiceUnavailable, Message: "tunneling backend unavailable"}}
	handler := New(Deps{SSHCertIssuer: &recordingSSHCertIssuer{}, TunnelIssuer: issuer})
	request := httptest.NewRequest(http.MethodPost, "/ssh/tunnel", strings.NewReader(`{"device_id":"d"}`))
	request.Header.Set("Authorization", "Bearer access-token-123")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if got, want := response.Code, http.StatusServiceUnavailable; got != want {
		t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
	}
}

// TestWriteIssueErrorLabelsPerRoute pins F-TN-A-2: the non-domain 500
// surfaced to the engineer must name the route's own issuer so operators
// can tell which subsystem actually failed. A single hardcoded label
// across the three handlers would misattribute /ssh/time-payload and
// /ssh/tunnel failures to "ssh cert issuer", sending operators down the
// wrong investigation path.
func TestWriteIssueErrorLabelsPerRoute(t *testing.T) {
	cases := []struct {
		name      string
		path      string
		body      string
		wantLabel string
		deps      func() Deps
	}{
		{
			name:      "ssh cert route names cert issuer",
			path:      "/ssh/cert",
			body:      `{"device_id":"d","principal_type":"operator","public_key":"ssh-ed25519 AAAA"}`,
			wantLabel: "ssh cert issuer failed",
			deps: func() Deps {
				return Deps{SSHCertIssuer: &recordingSSHCertIssuer{err: errors.New("boom")}}
			},
		},
		{
			name:      "time-payload route names time-payload issuer",
			path:      "/ssh/time-payload",
			body:      `{"device_id":"d","nonce":"n"}`,
			wantLabel: "time-payload issuer failed",
			deps: func() Deps {
				return Deps{
					SSHCertIssuer:     &recordingSSHCertIssuer{},
					TimePayloadIssuer: &recordingTimePayloadIssuer{err: errors.New("boom")},
				}
			},
		},
		{
			name:      "tunnel route names tunnel issuer",
			path:      "/ssh/tunnel",
			body:      `{"device_id":"d"}`,
			wantLabel: "tunnel issuer failed",
			deps: func() Deps {
				return Deps{
					SSHCertIssuer: &recordingSSHCertIssuer{},
					TunnelIssuer:  &recordingTunnelIssuer{err: errors.New("boom")},
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := New(tc.deps())
			request := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			request.Header.Set("Authorization", "Bearer access-token-123")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if got, want := response.Code, http.StatusInternalServerError; got != want {
				t.Fatalf("status = %d, want %d: %s", got, want, response.Body.String())
			}
			if got := response.Body.String(); !strings.Contains(got, tc.wantLabel) {
				t.Fatalf("body = %q, want contains %q", got, tc.wantLabel)
			}
		})
	}
}

type failingHealthChecker struct {
	err error
}

func (c failingHealthChecker) CheckHealth(context.Context) error {
	return c.err
}

// recordingSSHCertIssuer satisfies the post-LD-93-split SSHCertIssuer
// interface (cert-mint methods only). Time-payload + tunnel-open tests
// use the sibling recorder types defined below.
type recordingSSHCertIssuer struct {
	request        broker.SSHCertIssueRequest
	response       broker.SSHCertIssueResponse
	err            error
	handlerDenials []broker.HandlerDenial
	issueCalls     int
}

func (i *recordingSSHCertIssuer) IssueSSHCert(ctx context.Context, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
	i.request = request
	i.issueCalls++
	return i.response, i.err
}

func (i *recordingSSHCertIssuer) RecordSSHCertHandlerDenial(_ context.Context, denial broker.HandlerDenial) {
	i.handlerDenials = append(i.handlerDenials, denial)
}

// recordingTimePayloadIssuer satisfies the post-LD-93-split TimePayloadIssuer
// interface.
type recordingTimePayloadIssuer struct {
	request        broker.TimePayloadIssueRequest
	response       broker.TimePayloadIssueResponse
	err            error
	handlerDenials []broker.HandlerDenial
	issueCalls     int
}

func (i *recordingTimePayloadIssuer) IssueTimePayload(ctx context.Context, request broker.TimePayloadIssueRequest) (broker.TimePayloadIssueResponse, error) {
	i.request = request
	i.issueCalls++
	return i.response, i.err
}

func (i *recordingTimePayloadIssuer) RecordTimePayloadHandlerDenial(_ context.Context, denial broker.HandlerDenial) {
	i.handlerDenials = append(i.handlerDenials, denial)
}

// recordingTunnelIssuer satisfies the post-LD-93-split TunnelIssuer
// interface.
type recordingTunnelIssuer struct {
	request        broker.TunnelOpenRequest
	response       broker.TunnelOpenResponse
	err            error
	handlerDenials []broker.HandlerDenial
	issueCalls     int
}

func (i *recordingTunnelIssuer) OpenTunnel(ctx context.Context, request broker.TunnelOpenRequest) (broker.TunnelOpenResponse, error) {
	i.request = request
	i.issueCalls++
	return i.response, i.err
}

func (i *recordingTunnelIssuer) RecordTunnelHandlerDenial(_ context.Context, denial broker.HandlerDenial) {
	i.handlerDenials = append(i.handlerDenials, denial)
}
