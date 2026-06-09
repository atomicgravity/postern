package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ssh"
)

// TestIssueTimePayloadHappyPathProducesVerifiableJWS is the load-bearing
// success test for the TF-A pipeline: a well-formed request flows through
// every pipeline stage, the resulting JWS Compact serialization parses
// back via go-jose, the signature verifies against the test CA pubkey,
// and the payload carries all eight pinned fields (invariant R).
func TestIssueTimePayloadHappyPathProducesVerifiableJWS(t *testing.T) {
	caEd25519PublicKey, caSSHSigner := newTestEd25519SSHSigner(t)
	audit := &recordingAudit{}
	registry := &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123", FriendlyID: "prod-a012"}}
	policy := &recordingPolicy{}
	rateLimiter := &recordingRateLimiter{}
	issuer := newTestTimePayloadIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{
			Subject:  "sub-123",
			Email:    "engineer@example.com",
			Groups:   []string{"postern-engineers"},
			Class:    "user",
			ClientID: "cli-app-7",
		}},
		Registry:    registry,
		Policy:      policy,
		RateLimiter: rateLimiter,
		Signer:      SSHSigner{Signer: caSSHSigner},
		Audit:       audit,
		Clock:       fixedClock{now: time.Unix(1747000000, 0)},
		IDs:         fixedIDGenerator{id: ID{UUID: "01969cc1-2800-7000-8000-000000000001", Serial: 1}},
	})

	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	response, err := issuer.IssueTimePayload(context.Background(), TimePayloadIssueRequest{
		AccessToken: "access-token-123",
		DeviceID:    "prod-a012",
		Nonce:       nonce,
		UserAgent:   "postern/test",
		RemoteAddr:  "203.0.113.1:12345",
	})
	if err != nil {
		t.Fatalf("IssueTimePayload() error = %v", err)
	}
	if got, want := response.JTI, "01969cc1-2800-7000-8000-000000000001"; got != want {
		t.Fatalf("response.JTI = %q, want %q", got, want)
	}
	if response.TimePayload == "" {
		t.Fatal("response.TimePayload empty")
	}
	if strings.Count(response.TimePayload, ".") != 2 {
		t.Fatalf("time payload = %q, want exactly three dot-separated segments", response.TimePayload)
	}

	parsed, err := jose.ParseSigned(response.TimePayload, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("jose.ParseSigned() error = %v", err)
	}
	if len(parsed.Signatures) != 1 {
		t.Fatalf("signatures = %d, want 1", len(parsed.Signatures))
	}
	header := parsed.Signatures[0].Header
	if got, want := header.Algorithm, "EdDSA"; got != want {
		t.Fatalf("header.alg = %q, want %q", got, want)
	}
	if got, want := header.ExtraHeaders[jose.HeaderType], any("postern-timefix+jwt"); got != want {
		t.Fatalf("header.typ = %v, want %q", got, want)
	}
	// Defense-in-depth: the on-wire header must be exactly two fields.
	// Pull the protected header out as raw JSON and decode into a map
	// so we can assert the field set with no allowance for extras.
	if got := strictHeaderFields(t, response.TimePayload); !mapsHaveOnlyKeys(got, "alg", "typ") {
		t.Fatalf("header fields = %v, want exactly alg+typ", got)
	}

	verifiedPayload, err := parsed.Verify(caEd25519PublicKey)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(verifiedPayload, &claims); err != nil {
		t.Fatalf("Unmarshal(claims) error = %v", err)
	}
	if !mapsHaveOnlyKeys(claims, "iss", "aud", "device_serial", "nonce", "now", "issued_to", "jti", "iat") {
		t.Fatalf("payload claim set = %v, want exactly the eight pinned fields", keysOf(claims))
	}
	if got, want := claims["iss"], any("postern.broker"); got != want {
		t.Fatalf("iss = %v, want %q", got, want)
	}
	if got, want := claims["aud"], any("device-SERIAL123-timefix"); got != want {
		t.Fatalf("aud = %v, want %q", got, want)
	}
	if got, want := claims["device_serial"], any("SERIAL123"); got != want {
		t.Fatalf("device_serial = %v, want %q", got, want)
	}
	if got, want := claims["nonce"], any(nonce); got != want {
		t.Fatalf("nonce = %v, want %q", got, want)
	}
	if got, want := claims["issued_to"], any("sub-123"); got != want {
		t.Fatalf("issued_to = %v, want %q", got, want)
	}
	if got, want := claims["jti"], any("01969cc1-2800-7000-8000-000000000001"); got != want {
		t.Fatalf("jti = %v, want %q", got, want)
	}
	if got, want := claims["now"], any("2025-05-11T21:46:40Z"); got != want {
		t.Fatalf("now = %v, want %q", got, want)
	}
	// iat decodes as float64 through map[string]any — compare via numeric cast.
	if got, want := int64(claims["iat"].(float64)), int64(1747000000); got != want {
		t.Fatalf("iat = %d, want %d", got, want)
	}

	// Audit invariant: exactly two events on the happy path —
	// authorized + issued, joined on jti, both carrying the policy
	// mode label so operators can filter by endpoint.
	if got, want := audit.calls, 2; got != want {
		t.Fatalf("audit calls = %d, want %d", got, want)
	}
	if got, want := audit.events[0].Event, EventTimePayloadAuthorized; got != want {
		t.Fatalf("audit[0] = %q, want %q", got, want)
	}
	if got, want := audit.events[1].Event, EventTimePayloadIssued; got != want {
		t.Fatalf("audit[1] = %q, want %q", got, want)
	}
	if audit.events[0].JTI != audit.events[1].JTI {
		t.Fatalf("authorized.jti = %q, issued.jti = %q (must match)", audit.events[0].JTI, audit.events[1].JTI)
	}
	if got, want := audit.events[0].PrincipalType, ModeTimefix; got != want {
		t.Fatalf("audit.principal_type = %q, want %q", got, want)
	}
	for _, ev := range audit.events {
		if ev.PrincipalClass != "user" {
			t.Fatalf("event %q principal_class = %q, want %q", ev.Event, ev.PrincipalClass, "user")
		}
		if ev.ClientID != "cli-app-7" {
			t.Fatalf("event %q client_id = %q, want %q", ev.Event, ev.ClientID, "cli-app-7")
		}
	}
	if got, want := policy.request.Mode, ModeTimefix; got != want {
		t.Fatalf("policy.mode = %q, want %q", got, want)
	}
	if got, want := rateLimiter.request.Mode, ModeTimefix; got != want {
		t.Fatalf("ratelimit.mode = %q, want %q", got, want)
	}
}

// TestIssueTimePayloadPipelineFailureModes locks each pre-Sign failure
// path's denied_reason and audit-row count. Mirrors the LD-64 cert-mint
// failure-modes table but for /ssh/time-payload's denial classifications.
func TestIssueTimePayloadPipelineFailureModes(t *testing.T) {
	validNonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	_, caSSHSigner := newTestEd25519SSHSigner(t)

	cases := []struct {
		name            string
		mutate          func(*TimePayloadIssueRequest)
		verifierErr     error
		registryErr     error
		policyErr       error
		rateLimiterErr  error
		signerErr       error
		auditErr        error
		wantStatus      int
		wantDenyReason  string
		wantWrappedSub  string
		wantPolicyCalls int
		wantSignerCalls int
		wantAuditCalls  int
		wantEventOrder  []string
	}{
		{
			name:           "invalid access token",
			verifierErr:    errors.New("token signature invalid"),
			wantStatus:     http.StatusUnauthorized,
			wantDenyReason: DenyReasonInvalidAccessToken,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTimePayloadDenied},
		},
		{
			name:           "rate limit exceeded short-circuits before registry",
			rateLimiterErr: Error{StatusCode: http.StatusTooManyRequests, Message: "rate limit"},
			wantStatus:     http.StatusTooManyRequests,
			wantDenyReason: DenyReasonRateLimitExceeded,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTimePayloadDenied},
		},
		{
			name:           "missing device_id after trim",
			mutate:         func(r *TimePayloadIssueRequest) { r.DeviceID = "   " },
			wantStatus:     http.StatusBadRequest,
			wantDenyReason: DenyReasonMissingDeviceID,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTimePayloadDenied},
		},
		{
			name:           "missing nonce",
			mutate:         func(r *TimePayloadIssueRequest) { r.Nonce = "   " },
			wantStatus:     http.StatusBadRequest,
			wantDenyReason: DenyReasonMissingNonce,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTimePayloadDenied},
		},
		{
			name:           "nonce not base64url",
			mutate:         func(r *TimePayloadIssueRequest) { r.Nonce = "$$$not-base64$$$" },
			wantStatus:     http.StatusBadRequest,
			wantDenyReason: DenyReasonInvalidNonce,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTimePayloadDenied},
		},
		{
			name:           "nonce wrong byte length",
			mutate:         func(r *TimePayloadIssueRequest) { r.Nonce = base64.RawURLEncoding.EncodeToString(make([]byte, 16)) },
			wantStatus:     http.StatusBadRequest,
			wantDenyReason: DenyReasonInvalidNonce,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTimePayloadDenied},
		},
		{
			name:           "device not found",
			registryErr:    Error{StatusCode: http.StatusNotFound, Message: "device not found"},
			wantStatus:     http.StatusNotFound,
			wantDenyReason: DenyReasonDeviceNotFound,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTimePayloadDenied},
		},
		{
			name:            "authorization denied",
			policyErr:       Error{StatusCode: http.StatusForbidden, Message: "denied"},
			wantStatus:      http.StatusForbidden,
			wantDenyReason:  DenyReasonAuthorizationDenied,
			wantPolicyCalls: 1,
			wantAuditCalls:  1,
			wantEventOrder:  []string{EventTimePayloadDenied},
		},
		{
			name:            "policy unavailable",
			policyErr:       Error{StatusCode: http.StatusBadGateway, Message: "AVP down"},
			wantStatus:      http.StatusBadGateway,
			wantDenyReason:  DenyReasonPolicyUnavailable,
			wantPolicyCalls: 1,
			wantAuditCalls:  1,
			wantEventOrder:  []string{EventTimePayloadDenied},
		},
		{
			name:            "pre-sign audit failure short-circuits before sign",
			auditErr:        errors.New("cloudwatch down"),
			wantWrappedSub:  "record time payload audit event: cloudwatch down",
			wantPolicyCalls: 1,
			wantSignerCalls: 0,
			wantAuditCalls:  1,
		},
		{
			name:            "signer failure emits authorized+denied (no issued)",
			signerErr:       errors.New("kms down"),
			wantWrappedSub:  "sign time payload: kms down",
			wantPolicyCalls: 1,
			wantSignerCalls: 1,
			wantAuditCalls:  2,
			wantEventOrder:  []string{EventTimePayloadAuthorized, EventTimePayloadDenied},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit := &recordingAudit{err: tc.auditErr}
			policy := &recordingPolicy{err: tc.policyErr}
			rateLimiter := &recordingRateLimiter{err: tc.rateLimiterErr}
			registry := &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}, err: tc.registryErr}
			signer := &recordingSigner{publicKey: caSSHSigner.PublicKey(), inner: caSSHSigner, timePayloadErr: tc.signerErr}

			deps := testDeps{
				TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123"}, err: tc.verifierErr},
				Registry:      registry,
				Policy:        policy,
				RateLimiter:   rateLimiter,
				Signer:        signer,
				Audit:         audit,
				Clock:         fixedClock{now: time.Unix(1747000000, 0)},
				IDs:           fixedIDGenerator{id: ID{UUID: "tp-jti", Serial: 1}},
			}
			issuer := newTestTimePayloadIssuer(t, deps)

			request := TimePayloadIssueRequest{
				AccessToken: "good-token",
				DeviceID:    "prod-a012",
				Nonce:       validNonce,
				UserAgent:   "postern/test",
				RemoteAddr:  "203.0.113.1",
			}
			if tc.mutate != nil {
				tc.mutate(&request)
			}

			_, err := issuer.IssueTimePayload(context.Background(), request)
			if err == nil {
				t.Fatalf("IssueTimePayload() returned nil error, want failure")
			}
			if tc.wantStatus != 0 {
				var domainErr Error
				if !errors.As(err, &domainErr) {
					t.Fatalf("IssueTimePayload() error = %v, want broker.Error", err)
				}
				if got, want := domainErr.StatusCode, tc.wantStatus; got != want {
					t.Fatalf("status = %d, want %d", got, want)
				}
			}
			if tc.wantWrappedSub != "" {
				if !strings.Contains(err.Error(), tc.wantWrappedSub) {
					t.Fatalf("error = %v, want contains %q", err, tc.wantWrappedSub)
				}
			}
			if tc.wantDenyReason != "" {
				if len(audit.events) == 0 {
					t.Fatalf("no audit events; want first event with deny reason %q", tc.wantDenyReason)
				}
				// On the signer-failure path the first event is authorized;
				// the denied row is the second. On every other deny path
				// the first event is denied.
				denyEvent := audit.events[0]
				if tc.signerErr != nil {
					denyEvent = audit.events[len(audit.events)-1]
				}
				if got := denyEvent.DeniedReason; got != tc.wantDenyReason {
					t.Fatalf("denied_reason = %q, want %q", got, tc.wantDenyReason)
				}
			}
			if got, want := policy.calls, tc.wantPolicyCalls; got != want {
				t.Fatalf("policy calls = %d, want %d", got, want)
			}
			if got, want := signer.timePayloadCalls, tc.wantSignerCalls; got != want {
				t.Fatalf("signer calls = %d, want %d", got, want)
			}
			if got, want := audit.calls, tc.wantAuditCalls; got != want {
				t.Fatalf("audit calls = %d, want %d", got, want)
			}
			if len(tc.wantEventOrder) > 0 {
				if len(audit.events) != len(tc.wantEventOrder) {
					t.Fatalf("audit events count = %d, want %d", len(audit.events), len(tc.wantEventOrder))
				}
				for idx, want := range tc.wantEventOrder {
					if got := audit.events[idx].Event; got != want {
						t.Fatalf("audit events[%d].Event = %q, want %q", idx, got, want)
					}
				}
			}
		})
	}
}

// TestIssueTimePayloadSignerFailureEmitsSignerFailureReason locks the
// specific denied_reason on the signer-failure path: authorized fires first
// (pre-Sign), then a denied row with reason signer_failure. Cert-mint
// pipeline doesn't emit an explicit signer_failure deny row today; the
// time-payload pipeline does because the spec calls it out and it makes
// operator log queries trivial ("filter `denied_reason = signer_failure`").
func TestIssueTimePayloadSignerFailureEmitsSignerFailureReason(t *testing.T) {
	_, caSSHSigner := newTestEd25519SSHSigner(t)
	audit := &recordingAudit{}
	signer := &recordingSigner{publicKey: caSSHSigner.PublicKey(), inner: caSSHSigner, timePayloadErr: errors.New("kms down")}
	issuer := newTestTimePayloadIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123"}},
		Registry:      &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        signer,
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "sf-jti", Serial: 1}},
	})

	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	_, err := issuer.IssueTimePayload(context.Background(), TimePayloadIssueRequest{
		AccessToken: "access-token",
		DeviceID:    "prod-a012",
		Nonce:       nonce,
	})
	if err == nil {
		t.Fatalf("IssueTimePayload() returned nil error, want sign-failure wrap")
	}
	if len(audit.events) != 2 {
		t.Fatalf("audit events = %d, want 2 (authorized + signer_failure denied)", len(audit.events))
	}
	if audit.events[0].Event != EventTimePayloadAuthorized {
		t.Fatalf("audit[0] = %q, want %q", audit.events[0].Event, EventTimePayloadAuthorized)
	}
	if audit.events[1].Event != EventTimePayloadDenied {
		t.Fatalf("audit[1] = %q, want %q", audit.events[1].Event, EventTimePayloadDenied)
	}
	if audit.events[1].DeniedReason != DenyReasonSignerFailure {
		t.Fatalf("audit[1].denied_reason = %q, want %q", audit.events[1].DeniedReason, DenyReasonSignerFailure)
	}
	if audit.events[1].DeviceSerial != "SERIAL123" {
		t.Fatalf("audit[1].device_serial = %q, want %q (engineer + device established pre-sign)", audit.events[1].DeviceSerial, "SERIAL123")
	}
}

// TestIssueTimePayloadPostSignAuditFailureBestEffort locks the post-sign
// best-effort contract: if the issued audit row fails to record, the JWS
// still returns to the engineer (the payload is already signed and going
// out). Operators detect missing rows by joining authorized vs issued on
// jti rather than by request status.
func TestIssueTimePayloadPostSignAuditFailureBestEffort(t *testing.T) {
	_, caSSHSigner := newTestEd25519SSHSigner(t)
	audit := &recordingAudit{errs: []error{nil, errors.New("cloudwatch flake on issued")}}
	issuer := newTestTimePayloadIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123"}},
		Registry:      &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        SSHSigner{Signer: caSSHSigner},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "pf-jti", Serial: 1}},
	})

	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	response, err := issuer.IssueTimePayload(context.Background(), TimePayloadIssueRequest{
		AccessToken: "access-token",
		DeviceID:    "prod-a012",
		Nonce:       nonce,
	})
	if err != nil {
		t.Fatalf("IssueTimePayload() error = %v, want nil (post-sign audit is best-effort)", err)
	}
	if response.TimePayload == "" {
		t.Fatal("response.TimePayload empty")
	}
	if audit.calls != 2 {
		t.Fatalf("audit calls = %d, want 2", audit.calls)
	}
}

// TestIssueTimePayloadSkipsRegistryOnRateLimitDenial mirrors the cert-mint
// version of F-BROKER-1: a rate-limited request must NOT reach Registry.
// Closes the authenticated device-enumeration oracle on /ssh/time-payload
// too.
func TestIssueTimePayloadSkipsRegistryOnRateLimitDenial(t *testing.T) {
	registry := &recordingRegistry{device: DeviceRecord{Serial: "should-not-be-resolved"}}
	issuer := newTestTimePayloadIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123"}},
		Registry:      registry,
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{err: Error{StatusCode: http.StatusTooManyRequests, Message: "rate limit exceeded"}},
		Signer:        &recordingSigner{},
		Audit:         &recordingAudit{},
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "id", Serial: 1}},
	})

	nonce := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	_, err := issuer.IssueTimePayload(context.Background(), TimePayloadIssueRequest{
		AccessToken: "good-token",
		DeviceID:    "prod-a012",
		Nonce:       nonce,
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("IssueTimePayload() error = %v, want 429 broker.Error", err)
	}
	if registry.calls != 0 {
		t.Fatalf("registry.ResolveDevice calls = %d, want 0 (rate-limit must short-circuit before registry)", registry.calls)
	}
}

// TestRecordTimePayloadHandlerDenialEmitsTimePayloadDeniedEvent locks the
// handler-side pre-invocation audit path: missing-bearer / malformed-body
// produce a time_payload_denied row (not ssh_cert_denied) so operators can
// filter by endpoint without joining audit rows to request URLs.
func TestRecordTimePayloadHandlerDenialEmitsTimePayloadDeniedEvent(t *testing.T) {
	audit := &recordingAudit{}
	issuer := newTestTimePayloadIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{},
		Registry:      &recordingRegistry{},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        &recordingSigner{},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "handler-tp-jti", Serial: 1}},
	})

	issuer.RecordTimePayloadHandlerDenial(context.Background(), HandlerDenial{
		DeniedReason: DenyReasonMissingBearerToken,
		SourceIP:     "203.0.113.5",
		UserAgent:    "postern/test",
	})

	if got, want := audit.calls, 1; got != want {
		t.Fatalf("audit calls = %d, want %d", got, want)
	}
	got := audit.events[0]
	if got.Event != EventTimePayloadDenied {
		t.Fatalf("event = %q, want %q", got.Event, EventTimePayloadDenied)
	}
	if got.DeniedReason != DenyReasonMissingBearerToken {
		t.Fatalf("denied_reason = %q, want %q", got.DeniedReason, DenyReasonMissingBearerToken)
	}
	if got.PrincipalType != ModeTimefix {
		t.Fatalf("principal_type = %q, want %q", got.PrincipalType, ModeTimefix)
	}
	if got.JTI != "handler-tp-jti" {
		t.Fatalf("jti = %q, want %q", got.JTI, "handler-tp-jti")
	}
}

// newTestEd25519SSHSigner returns a fresh Ed25519 keypair as the underlying
// public key plus an ssh.Signer wrapping it — the same key serves both the
// JWS-side public verification key (passed directly into jose.Verify) and
// the SSH-side signing key (used through SSHSigner / kmsSSHSigner's
// adapter). Mirrors the broker's one-CA invariant.
func newTestEd25519SSHSigner(t *testing.T) (ed25519.PublicKey, ssh.Signer) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	return publicKey, signer
}

func strictHeaderFields(t *testing.T, compact string) map[string]any {
	t.Helper()
	segments := strings.Split(compact, ".")
	if len(segments) != 3 {
		t.Fatalf("compact = %q, want three segments", compact)
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(segments[0])
	if err != nil {
		t.Fatalf("DecodeString(header) error = %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(headerBytes, &fields); err != nil {
		t.Fatalf("Unmarshal(header) error = %v", err)
	}
	return fields
}

func mapsHaveOnlyKeys(m map[string]any, want ...string) bool {
	if len(m) != len(want) {
		return false
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
