package broker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSSHCertIssuerIssuesOperatorCert(t *testing.T) {
	caSigner := newTestSigner(t)
	publicKey := newTestAuthorizedPublicKey(t)
	audit := &recordingAudit{}
	registry := &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123", FriendlyID: "prod-a012"}}
	policy := &recordingPolicy{}
	rateLimiter := &recordingRateLimiter{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{
			Subject:  "sub-123",
			Email:    "engineer@example.com",
			Groups:   []string{"postern-engineers", "on-call"},
			Class:    "user",
			ClientID: "cli-app-7",
		}},
		Registry:    registry,
		Policy:      policy,
		RateLimiter: rateLimiter,
		Signer:      SSHSigner{Signer: caSigner},
		Audit:       audit,
		Clock:       fixedClock{now: time.Unix(1747000000, 0)},
		IDs:         fixedIDGenerator{id: ID{UUID: "01969cc1-2800-7000-8000-000000000001", Serial: 114392862794117120}},
	})

	response, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "access-token-123",
		DeviceID:      "prod-a012",
		PrincipalType: PrincipalTypeOperator,
		PublicKey:     publicKey,
		UserAgent:     "postern/test",
		RemoteAddr:    "203.0.113.1:12345",
	})
	if err != nil {
		t.Fatalf("IssueSSHCert() error = %v", err)
	}
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SSHCert))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(cert) error = %v", err)
	}
	cert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key type = %T, want *ssh.Certificate", parsedKey)
	}
	if got, want := cert.CertType, uint32(ssh.UserCert); got != want {
		t.Fatalf("cert type = %d, want %d", got, want)
	}
	if got, want := strings.Join(cert.ValidPrincipals, ","), "device-SERIAL123-operator"; got != want {
		t.Fatalf("principals = %q, want %q", got, want)
	}
	if got, want := cert.KeyId, "engineer_sub:sub-123;engineer_email:engineer@example.com;jti:01969cc1-2800-7000-8000-000000000001"; got != want {
		t.Fatalf("key id = %q, want %q", got, want)
	}
	wantExtensions := []string{
		"permit-X11-forwarding",
		"permit-agent-forwarding",
		"permit-port-forwarding",
		"permit-pty",
		"permit-user-rc",
	}
	for _, ext := range wantExtensions {
		if _, ok := cert.Extensions[ext]; !ok {
			t.Fatalf("extensions = %#v, want %q present", cert.Extensions, ext)
		}
	}
	if len(cert.Extensions) != len(wantExtensions) {
		t.Fatalf("extensions = %#v, want exactly the %d default extensions", cert.Extensions, len(wantExtensions))
	}
	if got, want := cert.ValidAfter, uint64(1746996400); got != want {
		t.Fatalf("valid after = %d, want %d", got, want)
	}
	if got, want := cert.ValidBefore, uint64(1747043200); got != want {
		t.Fatalf("valid before = %d, want %d", got, want)
	}
	if got, want := response.CAPubkeyFingerprint, ssh.FingerprintSHA256(caSigner.PublicKey()); got != want {
		t.Fatalf("CA fingerprint = %q, want %q", got, want)
	}
	if got, want := policy.request.AccessToken, "access-token-123"; got != want {
		t.Fatalf("policy access token = %q, want %q", got, want)
	}
	if got, want := audit.event.DeviceSerial, "SERIAL123"; got != want {
		t.Fatalf("audit serial = %q, want %q", got, want)
	}
	if got, want := strings.Join(audit.event.EngineerGroups, ","), "postern-engineers,on-call"; got != want {
		t.Fatalf("audit engineer groups = %q, want %q", got, want)
	}
	if got, want := rateLimiter.request.RequestID, "01969cc1-2800-7000-8000-000000000001"; got != want {
		t.Fatalf("rate limit request id = %q, want %q", got, want)
	}

	encoded, err := json.Marshal(audit.event)
	if err != nil {
		t.Fatalf("json.Marshal(audit.event) error = %v", err)
	}
	if got, want := string(encoded), `"engineer_groups":["postern-engineers","on-call"]`; !strings.Contains(got, want) {
		t.Fatalf("audit JSON = %s, want contains %q", got, want)
	}

	emptyGroups, err := json.Marshal(AuditEvent{Event: "ssh_cert_issued"})
	if err != nil {
		t.Fatalf("json.Marshal(empty AuditEvent) error = %v", err)
	}
	if strings.Contains(string(emptyGroups), "engineer_groups") {
		t.Fatalf("empty AuditEvent JSON = %s, want engineer_groups omitted", emptyGroups)
	}

	// Both the authorized and issued rows carry the principal class and the
	// caller's client_id (stamped wherever the caller identity is known).
	if len(audit.events) != 2 {
		t.Fatalf("audit events = %d, want 2 (authorized + issued)", len(audit.events))
	}
	for _, ev := range audit.events {
		if ev.PrincipalClass != "user" {
			t.Fatalf("%s principal_class = %q, want %q", ev.Event, ev.PrincipalClass, "user")
		}
		if ev.ClientID != "cli-app-7" {
			t.Fatalf("%s client_id = %q, want %q", ev.Event, ev.ClientID, "cli-app-7")
		}
	}
	if got, want := string(encoded), `"principal_class":"user"`; !strings.Contains(got, want) {
		t.Fatalf("audit JSON = %s, want contains %q", got, want)
	}
	if got, want := string(encoded), `"client_id":"cli-app-7"`; !strings.Contains(got, want) {
		t.Fatalf("audit JSON = %s, want contains %q", got, want)
	}

	// A caller with no client_id claim still carries principal_class, but
	// client_id is omitted (omitempty).
	noClientID, err := json.Marshal(AuditEvent{Event: "ssh_cert_issued", PrincipalClass: "user"})
	if err != nil {
		t.Fatalf("json.Marshal(no-client_id AuditEvent) error = %v", err)
	}
	if !strings.Contains(string(noClientID), `"principal_class":"user"`) {
		t.Fatalf("no-client_id AuditEvent JSON = %s, want principal_class present", noClientID)
	}
	if strings.Contains(string(noClientID), "client_id") {
		t.Fatalf("no-client_id AuditEvent JSON = %s, want client_id omitted", noClientID)
	}
}

// TestSSHCertIssuerIssuesTimefixCert locks the timefix cert-shape: the
// principal matches the device-side sshd ForceCommand binding, the
// validity window is 1970→3000 (the engineer's clock may be wildly
// wrong, which is the whole point of the recovery flow), the only
// critical option is force-command pointing at the on-device verifier,
// and the cert has no permit-pty extension (no interactive surface
// beyond the forced command). The audit row's PrincipalType is
// "timefix" so operators can filter cert-mint events by mode without
// inspecting the cert body.
func TestSSHCertIssuerIssuesTimefixCert(t *testing.T) {
	caSigner := newTestSigner(t)
	publicKey := newTestAuthorizedPublicKey(t)
	audit := &recordingAudit{}
	registry := &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123", FriendlyID: "prod-a012"}}
	policy := &recordingPolicy{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{
			Subject: "sub-123",
			Email:   "engineer@example.com",
			Groups:  []string{"postern-engineers"},
		}},
		Registry:    registry,
		Policy:      policy,
		RateLimiter: &recordingRateLimiter{},
		Signer:      SSHSigner{Signer: caSigner},
		Audit:       audit,
		Clock:       fixedClock{now: time.Unix(1747000000, 0)},
		IDs:         fixedIDGenerator{id: ID{UUID: "01969cc1-2800-7000-8000-000000000002", Serial: 114392862794117121}},
	})

	response, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "access-token-123",
		DeviceID:      "prod-a012",
		PrincipalType: PrincipalTypeTimefix,
		PublicKey:     publicKey,
		UserAgent:     "postern/test",
		RemoteAddr:    "203.0.113.1:12345",
	})
	if err != nil {
		t.Fatalf("IssueSSHCert(timefix) error = %v", err)
	}

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SSHCert))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(cert) error = %v", err)
	}
	cert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key type = %T, want *ssh.Certificate", parsedKey)
	}

	if got, want := cert.CertType, uint32(ssh.UserCert); got != want {
		t.Fatalf("cert type = %d, want %d", got, want)
	}
	if got, want := strings.Join(cert.ValidPrincipals, ","), "device-SERIAL123-timefix"; got != want {
		t.Fatalf("principals = %q, want %q", got, want)
	}
	wantValidAfter := uint64(time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	if got := cert.ValidAfter; got != wantValidAfter {
		t.Fatalf("valid after = %d, want %d (1970-01-01, Unix epoch — the floor any dead-RTC device can boot at)", got, wantValidAfter)
	}
	wantValidBefore := uint64(time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	if got := cert.ValidBefore; got != wantValidBefore {
		t.Fatalf("valid before = %d, want %d (3000-01-01)", got, wantValidBefore)
	}
	if got, want := cert.KeyId, "engineer_sub:sub-123;engineer_email:engineer@example.com;jti:01969cc1-2800-7000-8000-000000000002"; got != want {
		t.Fatalf("key id = %q, want %q", got, want)
	}
	if cert.Serial != 114392862794117121 {
		t.Fatalf("cert serial = %d, want 114392862794117121", cert.Serial)
	}
	if len(cert.Extensions) != 0 {
		t.Fatalf("extensions = %#v, want empty (no permit-pty on timefix cert)", cert.Extensions)
	}
	if got, want := len(cert.CriticalOptions), 1; got != want {
		t.Fatalf("critical options count = %d, want %d", got, want)
	}
	if got, want := cert.CriticalOptions["force-command"], "/usr/sbin/timefix-apply"; got != want {
		t.Fatalf("force-command = %q, want %q", got, want)
	}

	// Audit row: PrincipalType must be "timefix" (ModeTimefix) so operators
	// can filter cert-mint events by mode without inspecting the cert body.
	if len(audit.events) != 2 {
		t.Fatalf("audit events = %d, want 2 (authorized + issued)", len(audit.events))
	}
	for _, ev := range audit.events {
		if got, want := ev.PrincipalType, ModeTimefix; got != want {
			t.Fatalf("audit event %q PrincipalType = %q, want %q", ev.Event, got, want)
		}
	}

	// Policy must have been called with the timefix mode label so AVP
	// dispatches to MintTimefixCert rather than MintOperatorCert.
	if got, want := policy.request.Mode, ModeTimefix; got != want {
		t.Fatalf("policy.Mode = %q, want %q", got, want)
	}
}

func TestSSHCertIssuerRejectsInvalidPublicKey(t *testing.T) {
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{},
		Registry:      &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        SSHSigner{Signer: newTestSigner(t)},
		Audit:         &recordingAudit{},
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "id", Serial: 1}},
	})

	_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "access-token-123",
		DeviceID:      "device-123",
		PrincipalType: PrincipalTypeOperator,
		PublicKey:     "not-a-key",
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("IssueSSHCert() error = %v, want %d broker.Error", err, http.StatusBadRequest)
	}
}

// TestSSHCertIssuerRejectsCertShapedPublicKey guards against authenticated DoS:
// ssh.ParseAuthorizedKey accepts certificate-shaped inputs and returns an
// *ssh.Certificate; the downstream SignCert path panics with "unknown
// certificate type for key type" when Key is itself a certificate. The
// pipeline must reject the input at the handler boundary with a 400 instead
// of letting it reach the signer.
func TestSSHCertIssuerRejectsCertShapedPublicKey(t *testing.T) {
	caSigner := newTestSigner(t)
	innerPubKey := newTestAuthorizedPublicKey(t)
	innerKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(innerPubKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(inner) error = %v", err)
	}
	// Build a syntactically valid cert that can be marshalled as an
	// authorized_keys line. The cert's contents don't need to be cryptographically
	// valid; ParseAuthorizedKey only cares about the on-wire shape.
	innerCert := &ssh.Certificate{
		Key:             innerKey,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "attacker",
		ValidPrincipals: []string{"attacker"},
		ValidAfter:      1,
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := innerCert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("SignCert(inner) error = %v", err)
	}
	certShapedKey := string(ssh.MarshalAuthorizedKey(innerCert))

	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{},
		Registry:      &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        SSHSigner{Signer: caSigner},
		Audit:         &recordingAudit{},
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "id", Serial: 1}},
	})

	_, err = issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "access-token-123",
		DeviceID:      "device-123",
		PrincipalType: PrincipalTypeOperator,
		PublicKey:     certShapedKey,
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("IssueSSHCert() error = %v, want %d broker.Error", err, http.StatusBadRequest)
	}
	if !strings.Contains(domainErr.Message, "must be a bare public key") {
		t.Fatalf("error message = %q, want explanation of bare-public-key requirement", domainErr.Message)
	}
}

// TestSSHCertIssuerPipelineFailureModes locks the cert-mint pipeline ordering:
// token-verify → parse-key → rate-limit → registry → policy → audit-authorized
// → sign → audit-issued. Each step's failure emits a best-effort deny audit
// (or, post-policy, a phantom-free pre-sign authorized event) before
// short-circuiting. The audit-authorized-fails case is the regression guard
// for "no KMS Sign call without a successful pre-sign audit emission" —
// without it, engineers would be rate-limit-charged and KMS-billed without
// an audit trail on a CloudWatch failure.
//
// Sign-failure no longer leaves a phantom "issued" row: the post-sign
// issued audit only fires after Sign returns nil. The pre-sign "authorized"
// row is still present, which is the intended behavior — operators can
// query for authorized-without-matching-issued to find sign-failure cases.
//
// Post-sign-audit-fails is the new best-effort case: the cert is delivered
// to the engineer with a logged warning when the issuance audit fails.
// Operators detect missing issued rows by joining authorized vs issued on
// `jti` rather than by request status.
func TestSSHCertIssuerPipelineFailureModes(t *testing.T) {
	publicKey := newTestAuthorizedPublicKey(t)
	caSigner := newTestSigner(t)

	cases := []struct {
		name             string
		rateLimiterErr   error
		policyErr        error
		auditErr         error   // legacy: all-calls error; if set without auditErrs, applies to every call
		auditErrs        []error // per-call errors; nil entries succeed
		signerErr        error
		wantStatus       int
		wantWrappedSub   string
		wantPolicyCalls  int
		wantSignerCalls  int
		wantAuditCalls   int
		wantSuccess      bool     // true when the test expects a cert to be returned
		wantDenialReason string   // expected DeniedReason on first audit event when wantSuccess=false
		wantEventOrder   []string // expected Event values in order when len > 0
	}{
		{
			name:             "rate-limit denial emits deny audit and short-circuits",
			rateLimiterErr:   Error{StatusCode: http.StatusTooManyRequests, Message: "rate limit exceeded"},
			wantStatus:       http.StatusTooManyRequests,
			wantPolicyCalls:  0,
			wantSignerCalls:  0,
			wantAuditCalls:   1,
			wantDenialReason: DenyReasonRateLimitExceeded,
			wantEventOrder:   []string{EventCertDenied},
		},
		{
			name:             "policy denial emits deny audit and short-circuits",
			policyErr:        Error{StatusCode: http.StatusForbidden, Message: "denied"},
			wantStatus:       http.StatusForbidden,
			wantPolicyCalls:  1,
			wantSignerCalls:  0,
			wantAuditCalls:   1,
			wantDenialReason: DenyReasonAuthorizationDenied,
			wantEventOrder:   []string{EventCertDenied},
		},
		{
			name:             "policy unavailable maps to policy_unavailable",
			policyErr:        Error{StatusCode: http.StatusBadGateway, Message: "AVP down"},
			wantStatus:       http.StatusBadGateway,
			wantPolicyCalls:  1,
			wantSignerCalls:  0,
			wantAuditCalls:   1,
			wantDenialReason: DenyReasonPolicyUnavailable,
			wantEventOrder:   []string{EventCertDenied},
		},
		{
			name:            "pre-sign audit failure surfaces before sign",
			auditErr:        errors.New("cloudwatch down"),
			wantWrappedSub:  "record SSH cert audit event: cloudwatch down",
			wantPolicyCalls: 1,
			wantSignerCalls: 0,
			wantAuditCalls:  1,
		},
		{
			name:             "sign failure emits ssh_cert_denied with signer_failure",
			signerErr:        errors.New("kms down"),
			wantWrappedSub:   "sign SSH cert: kms down",
			wantPolicyCalls:  1,
			wantSignerCalls:  1,
			wantAuditCalls:   2,
			wantEventOrder:   []string{EventCertAuthorized, EventCertDenied},
			wantDenialReason: DenyReasonSignerFailure,
		},
		{
			name:            "post-sign audit failure is best-effort — cert still returned",
			auditErrs:       []error{nil, errors.New("cloudwatch flake on issued")},
			wantPolicyCalls: 1,
			wantSignerCalls: 1,
			wantAuditCalls:  2,
			wantSuccess:     true,
			wantEventOrder:  []string{EventCertAuthorized, EventCertIssued},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			audit := &recordingAudit{err: tc.auditErr, errs: tc.auditErrs}
			policy := &recordingPolicy{err: tc.policyErr}
			rateLimiter := &recordingRateLimiter{err: tc.rateLimiterErr}
			signer := &recordingSigner{publicKey: caSigner.PublicKey(), inner: caSigner, err: tc.signerErr}

			issuer := newTestIssuer(t, testDeps{
				TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123", Email: "engineer@example.com"}},
				Registry:      &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123", FriendlyID: "prod-a012"}},
				Policy:        policy,
				RateLimiter:   rateLimiter,
				Signer:        signer,
				Audit:         audit,
				Clock:         fixedClock{now: time.Unix(1747000000, 0)},
				IDs:           fixedIDGenerator{id: ID{UUID: "01969cc1-2800-7000-8000-000000000001", Serial: 114392862794117120}},
			})

			response, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
				AccessToken:   "access-token-123",
				DeviceID:      "prod-a012",
				PrincipalType: PrincipalTypeOperator,
				PublicKey:     publicKey,
				UserAgent:     "postern/test",
				RemoteAddr:    "203.0.113.1:12345",
			})
			if tc.wantSuccess {
				if err != nil {
					t.Fatalf("IssueSSHCert() error = %v, want nil", err)
				}
				if strings.TrimSpace(response.SSHCert) == "" {
					t.Fatalf("IssueSSHCert() returned empty cert on best-effort success path")
				}
			} else {
				if err == nil {
					t.Fatalf("IssueSSHCert() returned nil error, want failure")
				}
				if tc.wantStatus != 0 {
					var domainErr Error
					if !errors.As(err, &domainErr) {
						t.Fatalf("IssueSSHCert() error = %v, want broker.Error", err)
					}
					if got, want := domainErr.StatusCode, tc.wantStatus; got != want {
						t.Fatalf("status = %d, want %d", got, want)
					}
				}
				if tc.wantWrappedSub != "" {
					if !strings.Contains(err.Error(), tc.wantWrappedSub) {
						t.Fatalf("IssueSSHCert() error = %v, want contains %q", err, tc.wantWrappedSub)
					}
				}
			}
			if got, want := policy.calls, tc.wantPolicyCalls; got != want {
				t.Fatalf("policy calls = %d, want %d", got, want)
			}
			if got, want := audit.calls, tc.wantAuditCalls; got != want {
				t.Fatalf("audit calls = %d, want %d", got, want)
			}
			if signer.calls != tc.wantSignerCalls {
				t.Fatalf("signer calls = %d, want %d", signer.calls, tc.wantSignerCalls)
			}
			if tc.wantDenialReason != "" {
				var denyEvent *AuditEvent
				for i := range audit.events {
					if audit.events[i].Event == EventCertDenied {
						denyEvent = &audit.events[i]
					}
				}
				if denyEvent == nil {
					t.Fatalf("no ssh_cert_denied event recorded; want deny with reason %q", tc.wantDenialReason)
				}
				if got, want := denyEvent.DeniedReason, tc.wantDenialReason; got != want {
					t.Fatalf("denial reason = %q, want %q", got, want)
				}
			}
			if len(tc.wantEventOrder) > 0 {
				if len(audit.events) != len(tc.wantEventOrder) {
					t.Fatalf("audit events count = %d, want %d", len(audit.events), len(tc.wantEventOrder))
				}
				for i, want := range tc.wantEventOrder {
					if got := audit.events[i].Event; got != want {
						t.Fatalf("audit events[%d].Event = %q, want %q", i, got, want)
					}
				}
			}
		})
	}
}

// TestSSHCertIssuerEmitsAuthorizedAndIssuedOnSuccess locks the two-event audit
// shape for the happy path: ssh_cert_authorized before sign, ssh_cert_issued
// after. Both events carry the same metadata (cert serial, JTI, validity
// window, engineer + device identity) so operators can join them on `jti`
// to confirm issuance follow-through.
func TestSSHCertIssuerEmitsAuthorizedAndIssuedOnSuccess(t *testing.T) {
	caSigner := newTestSigner(t)
	publicKey := newTestAuthorizedPublicKey(t)
	audit := &recordingAudit{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123", Email: "engineer@example.com"}},
		Registry:      &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123", FriendlyID: "prod-a012"}},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        SSHSigner{Signer: caSigner},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "01969cc1-2800-7000-8000-000000000001", Serial: 114392862794117120}},
	})

	_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "access-token-123",
		DeviceID:      "prod-a012",
		PrincipalType: PrincipalTypeOperator,
		PublicKey:     publicKey,
	})
	if err != nil {
		t.Fatalf("IssueSSHCert() error = %v", err)
	}
	if got, want := audit.calls, 2; got != want {
		t.Fatalf("audit calls = %d, want %d", got, want)
	}
	if got, want := audit.events[0].Event, EventCertAuthorized; got != want {
		t.Fatalf("first audit event = %q, want %q", got, want)
	}
	if got, want := audit.events[1].Event, EventCertIssued; got != want {
		t.Fatalf("second audit event = %q, want %q", got, want)
	}
	// The two events must carry the same JTI and CertSerial so operators
	// can join them. Any drift here breaks audit reconstruction.
	if got, want := audit.events[0].JTI, audit.events[1].JTI; got != want {
		t.Fatalf("JTI mismatch between authorized (%q) and issued (%q)", got, want)
	}
	if got, want := audit.events[0].CertSerial, audit.events[1].CertSerial; got != want {
		t.Fatalf("CertSerial mismatch between authorized (%q) and issued (%q)", got, want)
	}
}

// TestSSHCertIssuerDeniesUnverifiedToken locks the deny-audit emission for
// the token-verify path. Engineer fields stay empty (no engineer identity
// established) but the request metadata (device_id_used, source_ip, JTI) is
// recorded so operators can correlate failed-auth attempts by IP.
func TestSSHCertIssuerDeniesUnverifiedToken(t *testing.T) {
	audit := &recordingAudit{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{err: errors.New("token signature invalid")},
		Registry:      &recordingRegistry{},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        &recordingSigner{},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "deny-token-jti", Serial: 1}},
	})

	_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "bad-token",
		DeviceID:      "prod-a012",
		PrincipalType: PrincipalTypeOperator,
		PublicKey:     "ssh-ed25519 AAAA",
		RemoteAddr:    "203.0.113.1:12345",
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("IssueSSHCert() error = %v, want 401 broker.Error", err)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	got := audit.events[0]
	if got.Event != EventCertDenied {
		t.Fatalf("event = %q, want %q", got.Event, EventCertDenied)
	}
	if got.DeniedReason != DenyReasonInvalidAccessToken {
		t.Fatalf("denied_reason = %q, want %q", got.DeniedReason, DenyReasonInvalidAccessToken)
	}
	if got.DeviceIDUsed != "prod-a012" {
		t.Fatalf("device_id_used = %q, want %q", got.DeviceIDUsed, "prod-a012")
	}
	if got.JTI != "deny-token-jti" {
		t.Fatalf("jti = %q, want %q", got.JTI, "deny-token-jti")
	}
	if got.EngineerSub != "" {
		t.Fatalf("engineer_sub = %q, want empty (no engineer established)", got.EngineerSub)
	}
	// Pre-identity deny: the principal class and client_id are unknown, so
	// both are omitted just like engineer_sub.
	if got.PrincipalClass != "" {
		t.Fatalf("principal_class = %q, want empty (no caller identity established)", got.PrincipalClass)
	}
	if got.ClientID != "" {
		t.Fatalf("client_id = %q, want empty (no caller identity established)", got.ClientID)
	}
}

// TestSSHCertIssuerDeniesUnknownDevice locks the deny-audit reason for the
// 404-from-registry path. Engineer identity is established (so engineer_sub
// is populated) but device_serial isn't.
func TestSSHCertIssuerDeniesUnknownDevice(t *testing.T) {
	audit := &recordingAudit{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123", Class: "machine", ClientID: "svc-42"}},
		Registry:      &recordingRegistry{err: Error{StatusCode: http.StatusNotFound, Message: "device not found"}},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        &recordingSigner{},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "deny-device-jti", Serial: 1}},
	})

	_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "good-token",
		DeviceID:      "missing-device",
		PrincipalType: PrincipalTypeOperator,
		PublicKey:     newTestAuthorizedPublicKey(t),
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusNotFound {
		t.Fatalf("IssueSSHCert() error = %v, want 404 broker.Error", err)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	got := audit.events[0]
	if got.DeniedReason != DenyReasonDeviceNotFound {
		t.Fatalf("denied_reason = %q, want %q", got.DeniedReason, DenyReasonDeviceNotFound)
	}
	if got.EngineerSub != "sub-123" {
		t.Fatalf("engineer_sub = %q, want %q", got.EngineerSub, "sub-123")
	}
	// Post-identity deny: the caller class and client_id are known by the time
	// the device lookup fails, so the deny row carries them.
	if got.PrincipalClass != "machine" {
		t.Fatalf("principal_class = %q, want %q", got.PrincipalClass, "machine")
	}
	if got.ClientID != "svc-42" {
		t.Fatalf("client_id = %q, want %q", got.ClientID, "svc-42")
	}
	if got.DeviceSerial != "" {
		t.Fatalf("device_serial = %q, want empty (registry never resolved)", got.DeviceSerial)
	}
}

// TestSSHCertIssuerDeniesInvalidPrincipalType locks the audit emission for
// the unknown-principal-type path (anything other than operator / timefix).
// Engineer identity is NOT established yet — principal-type validation
// happens before TokenVerifier — so the deny carries only the request's
// transport metadata and JTI. Operators see `invalid_principal_type` as
// the reason; attackers fuzzing the wire format leave a trail.
func TestSSHCertIssuerDeniesInvalidPrincipalType(t *testing.T) {
	audit := &recordingAudit{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{},
		Registry:      &recordingRegistry{},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        &recordingSigner{},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "deny-pt-jti", Serial: 1}},
	})

	_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "access-token-123",
		DeviceID:      "device-123",
		PrincipalType: "root",
		PublicKey:     "ssh-ed25519 AAAA",
		RemoteAddr:    "203.0.113.1:12345",
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("IssueSSHCert() error = %v, want 400 broker.Error", err)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	if got := audit.events[0].DeniedReason; got != DenyReasonInvalidPrincipalType {
		t.Fatalf("denied_reason = %q, want %q", got, DenyReasonInvalidPrincipalType)
	}
}

// TestSSHCertIssuerDeniesMissingDeviceID locks the missing-device-id audit
// path. Engineer identity IS established (token verify ran), rate-limit
// budget IS consumed (the engineer's runaway-script defense), and only
// then does the empty device_id surface as a 400.
func TestSSHCertIssuerDeniesMissingDeviceID(t *testing.T) {
	audit := &recordingAudit{}
	rateLimiter := &recordingRateLimiter{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123"}},
		Registry:      &recordingRegistry{},
		Policy:        &recordingPolicy{},
		RateLimiter:   rateLimiter,
		Signer:        &recordingSigner{},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "deny-id-jti", Serial: 1}},
	})

	_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "access-token-123",
		DeviceID:      "   ", // whitespace-only collapses to empty after trim
		PrincipalType: PrincipalTypeOperator,
		PublicKey:     newTestAuthorizedPublicKey(t),
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("IssueSSHCert() error = %v, want 400 broker.Error", err)
	}
	if rateLimiter.calls != 1 {
		t.Fatalf("rate limiter calls = %d, want 1 (budget should be consumed even on missing-field)", rateLimiter.calls)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	if got := audit.events[0].DeniedReason; got != DenyReasonMissingDeviceID {
		t.Fatalf("denied_reason = %q, want %q", got, DenyReasonMissingDeviceID)
	}
	if got := audit.events[0].EngineerSub; got != "sub-123" {
		t.Fatalf("engineer_sub = %q, want %q", got, "sub-123")
	}
}

// TestSSHCertIssuerDeniesMissingPublicKey locks the missing-public-key audit
// path. By design this runs AFTER AVP allow — an unauthorized engineer with
// no public_key sees authorization_denied, not missing_public_key. An
// authorized engineer with empty key sees the explicit missing_public_key
// denial so they can fix their CLI.
func TestSSHCertIssuerDeniesMissingPublicKey(t *testing.T) {
	audit := &recordingAudit{}
	policy := &recordingPolicy{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123"}},
		Registry:      &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
		Policy:        policy,
		RateLimiter:   &recordingRateLimiter{},
		Signer:        &recordingSigner{},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "deny-key-jti", Serial: 1}},
	})

	_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "access-token-123",
		DeviceID:      "device-123",
		PrincipalType: PrincipalTypeOperator,
		PublicKey:     "   ",
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("IssueSSHCert() error = %v, want 400 broker.Error", err)
	}
	if policy.calls != 1 {
		t.Fatalf("policy calls = %d, want 1 (public_key check must run AFTER AVP allow)", policy.calls)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	if got := audit.events[0].DeniedReason; got != DenyReasonMissingPublicKey {
		t.Fatalf("denied_reason = %q, want %q", got, DenyReasonMissingPublicKey)
	}
}

// TestSSHCertIssuerRecordHandlerDenial unit-tests the pre-invocation audit
// helper used by the HTTP handler for missing-bearer and malformed-body
// cases. JTI is generated locally; engineer/device fields stay empty.
func TestSSHCertIssuerRecordHandlerDenial(t *testing.T) {
	audit := &recordingAudit{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{},
		Registry:      &recordingRegistry{},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        &recordingSigner{},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "handler-jti", Serial: 1}},
	})

	issuer.RecordSSHCertHandlerDenial(context.Background(), HandlerDenial{
		DeniedReason: DenyReasonMissingBearerToken,
		SourceIP:     "203.0.113.5",
		UserAgent:    "postern/test",
	})

	if got, want := audit.calls, 1; got != want {
		t.Fatalf("audit calls = %d, want %d", got, want)
	}
	got := audit.events[0]
	if got.Event != EventCertDenied {
		t.Fatalf("event = %q, want %q", got.Event, EventCertDenied)
	}
	if got.DeniedReason != DenyReasonMissingBearerToken {
		t.Fatalf("denied_reason = %q, want %q", got.DeniedReason, DenyReasonMissingBearerToken)
	}
	if got.JTI != "handler-jti" {
		t.Fatalf("jti = %q, want %q", got.JTI, "handler-jti")
	}
	if got.SourceIP != "203.0.113.5" {
		t.Fatalf("source_ip = %q, want %q", got.SourceIP, "203.0.113.5")
	}
	if got.EngineerSub != "" {
		t.Fatalf("engineer_sub = %q, want empty (engineer identity not established pre-invocation)", got.EngineerSub)
	}
}

// TestSSHCertIssuerSkipsRegistryOnRateLimitDenial locks F-BROKER-1: a
// rate-limited request must NOT reach Registry. This closes the
// authenticated device-enumeration oracle (404 vs other statuses leaking
// device existence) by ensuring the rate-limit gate runs first.
func TestSSHCertIssuerSkipsRegistryOnRateLimitDenial(t *testing.T) {
	registry := &recordingRegistry{device: DeviceRecord{Serial: "should-not-be-resolved"}}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123"}},
		Registry:      registry,
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{err: Error{StatusCode: http.StatusTooManyRequests, Message: "rate limit exceeded"}},
		Signer:        &recordingSigner{},
		Audit:         &recordingAudit{},
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "id", Serial: 1}},
	})

	_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:   "good-token",
		DeviceID:      "prod-a012",
		PrincipalType: PrincipalTypeOperator,
		PublicKey:     newTestAuthorizedPublicKey(t),
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("IssueSSHCert() error = %v, want 429 broker.Error", err)
	}
	if registry.calls != 0 {
		t.Fatalf("registry.ResolveDevice calls = %d, want 0 (rate-limit must short-circuit before registry)", registry.calls)
	}
}

// issueOperatorCertForTTL mints an operator cert for the given caller class
// and requested lifetime, returning the parsed cert so callers can assert on
// the validity window. The clock is fixed so ValidAfter/ValidBefore are
// deterministic.
func issueOperatorCertForTTL(t *testing.T, class string, byClass map[string]time.Duration, operatorTTL time.Duration, requestedMinutes int32) *ssh.Certificate {
	t.Helper()
	caSigner := newTestSigner(t)
	publicKey := newTestAuthorizedPublicKey(t)
	policy := &recordingPolicy{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier:      fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123", Class: class}},
		Registry:           &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
		Policy:             policy,
		RateLimiter:        &recordingRateLimiter{},
		Signer:             SSHSigner{Signer: caSigner},
		Audit:              &recordingAudit{},
		Clock:              fixedClock{now: time.Unix(1747000000, 0)},
		IDs:                fixedIDGenerator{id: ID{UUID: "ttl-jti", Serial: 1}},
		OperatorTTL:        operatorTTL,
		OperatorTTLByClass: byClass,
	})

	response, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:        "access-token-123",
		DeviceID:           "prod-a012",
		PrincipalType:      PrincipalTypeOperator,
		PublicKey:          publicKey,
		MaxLifetimeMinutes: requestedMinutes,
		RemoteAddr:         "203.0.113.1:12345",
	})
	if err != nil {
		t.Fatalf("IssueSSHCert() error = %v", err)
	}

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SSHCert))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(cert) error = %v", err)
	}
	cert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		t.Fatalf("parsed key type = %T, want *ssh.Certificate", parsedKey)
	}
	return cert
}

// TestSSHCertIssuerPerClassTTLCeiling locks the per-class operator-cert
// ceiling: a machine caller with no request gets the machine ceiling; a
// user/unmapped caller falls back to the operator default. The window is
// now+ceiling for ValidBefore, with the fixed clock-skew padding on
// ValidAfter regardless of class.
func TestSSHCertIssuerPerClassTTLCeiling(t *testing.T) {
	byClass := map[string]time.Duration{"machine": time.Hour}
	const operatorDefault = 12 * time.Hour
	now := time.Unix(1747000000, 0)
	wantValidAfter := uint64(now.Add(-OperatorClockSkewPadding).Unix())

	tests := []struct {
		name            string
		class           string
		wantValidBefore uint64
	}{
		{name: "machine class uses its own ceiling", class: "machine", wantValidBefore: uint64(now.Add(time.Hour).Unix())},
		{name: "user class falls back to operator default", class: "user", wantValidBefore: uint64(now.Add(operatorDefault).Unix())},
		{name: "unmapped class falls back to operator default", class: "robot", wantValidBefore: uint64(now.Add(operatorDefault).Unix())},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := issueOperatorCertForTTL(t, tc.class, byClass, operatorDefault, 0)
			if got := cert.ValidAfter; got != wantValidAfter {
				t.Fatalf("valid after = %d, want %d", got, wantValidAfter)
			}
			if got := cert.ValidBefore; got != tc.wantValidBefore {
				t.Fatalf("valid before = %d, want %d", got, tc.wantValidBefore)
			}
		})
	}
}

// TestSSHCertIssuerRequestedTTLClamping locks the propose-and-clamp rule: a
// request below the ceiling is honored; a request above the ceiling is clamped
// down to the ceiling (not denied), matching the tunnel default-substitution
// behavior so an omitted request can't bypass a Cedar `<= N` gate.
func TestSSHCertIssuerRequestedTTLClamping(t *testing.T) {
	const operatorDefault = 12 * time.Hour
	now := time.Unix(1747000000, 0)

	t.Run("request below ceiling honored", func(t *testing.T) {
		cert := issueOperatorCertForTTL(t, "user", nil, operatorDefault, 120)
		if got, want := cert.ValidBefore, uint64(now.Add(2*time.Hour).Unix()); got != want {
			t.Fatalf("valid before = %d, want %d (2h request honored)", got, want)
		}
	})

	t.Run("request above ceiling clamped", func(t *testing.T) {
		cert := issueOperatorCertForTTL(t, "machine", map[string]time.Duration{"machine": time.Hour}, operatorDefault, 600)
		if got, want := cert.ValidBefore, uint64(now.Add(time.Hour).Unix()); got != want {
			t.Fatalf("valid before = %d, want %d (clamped to 1h machine ceiling)", got, want)
		}
	})
}

// TestSSHCertIssuerNegativeTTLDenied locks that a negative requested lifetime
// is a 400 with the shared max_lifetime_exceeds_ceiling deny reason — the same
// shape the tunnel pipeline emits.
func TestSSHCertIssuerNegativeTTLDenied(t *testing.T) {
	audit := &recordingAudit{}
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123", Class: "user"}},
		Registry:      &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
		Policy:        &recordingPolicy{},
		RateLimiter:   &recordingRateLimiter{},
		Signer:        &recordingSigner{},
		Audit:         audit,
		Clock:         fixedClock{now: time.Unix(1747000000, 0)},
		IDs:           fixedIDGenerator{id: ID{UUID: "neg-jti", Serial: 1}},
	})

	_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:        "access-token-123",
		DeviceID:           "prod-a012",
		PrincipalType:      PrincipalTypeOperator,
		PublicKey:          newTestAuthorizedPublicKey(t),
		MaxLifetimeMinutes: -5,
		RemoteAddr:         "203.0.113.1:12345",
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("IssueSSHCert() error = %v, want 400 broker.Error", err)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	if got := audit.events[0].DeniedReason; got != DenyReasonMaxLifetimeExceedsCeiling {
		t.Fatalf("denied_reason = %q, want %q", got, DenyReasonMaxLifetimeExceedsCeiling)
	}
}

// TestSSHCertIssuerInjectsRequestedTTLPolicyContext locks that Cedar sees the
// resolved (clamped, default-substituted) lifetime as
// context.requested_cert_ttl_minutes (an int64), so policy can tighten further
// but an omitted request can't bypass a `<= N` gate.
func TestSSHCertIssuerInjectsRequestedTTLPolicyContext(t *testing.T) {
	const operatorDefault = 12 * time.Hour

	t.Run("omitted request uses resolved ceiling", func(t *testing.T) {
		policy := &recordingPolicy{}
		issuer := newTestIssuer(t, testDeps{
			TokenVerifier:      fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123", Class: "machine"}},
			Registry:           &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
			Policy:             policy,
			RateLimiter:        &recordingRateLimiter{},
			Signer:             SSHSigner{Signer: newTestSigner(t)},
			Audit:              &recordingAudit{},
			Clock:              fixedClock{now: time.Unix(1747000000, 0)},
			IDs:                fixedIDGenerator{id: ID{UUID: "ctx-jti", Serial: 1}},
			OperatorTTLByClass: map[string]time.Duration{"machine": time.Hour},
			OperatorTTL:        operatorDefault,
		})

		_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
			AccessToken:   "access-token-123",
			DeviceID:      "prod-a012",
			PrincipalType: PrincipalTypeOperator,
			PublicKey:     newTestAuthorizedPublicKey(t),
		})
		if err != nil {
			t.Fatalf("IssueSSHCert() error = %v", err)
		}
		got, ok := policy.request.Context["requested_cert_ttl_minutes"]
		if !ok {
			t.Fatalf("policy.Context missing requested_cert_ttl_minutes; got %v", policy.request.Context)
		}
		if want := int64(60); got != want {
			t.Fatalf("requested_cert_ttl_minutes = %v, want %v (resolved 1h ceiling, not engineer's zero)", got, want)
		}
	})

	t.Run("request below ceiling surfaces the request", func(t *testing.T) {
		policy := &recordingPolicy{}
		issuer := newTestIssuer(t, testDeps{
			TokenVerifier: fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123", Class: "user"}},
			Registry:      &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
			Policy:        policy,
			RateLimiter:   &recordingRateLimiter{},
			Signer:        SSHSigner{Signer: newTestSigner(t)},
			Audit:         &recordingAudit{},
			Clock:         fixedClock{now: time.Unix(1747000000, 0)},
			IDs:           fixedIDGenerator{id: ID{UUID: "ctx-jti", Serial: 1}},
			OperatorTTL:   operatorDefault,
		})

		_, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
			AccessToken:        "access-token-123",
			DeviceID:           "prod-a012",
			PrincipalType:      PrincipalTypeOperator,
			PublicKey:          newTestAuthorizedPublicKey(t),
			MaxLifetimeMinutes: 90,
		})
		if err != nil {
			t.Fatalf("IssueSSHCert() error = %v", err)
		}
		if got, want := policy.request.Context["requested_cert_ttl_minutes"], int64(90); got != want {
			t.Fatalf("requested_cert_ttl_minutes = %v, want %v", got, want)
		}
	})
}

// TestSSHCertIssuerTimefixIgnoresTTLRequest locks that the timefix cert's
// fixed 1970→3000 window is class-independent and unaffected by a requested
// lifetime, and that the cert pipeline injects no requested_cert_ttl_minutes
// context for timefix requests.
func TestSSHCertIssuerTimefixIgnoresTTLRequest(t *testing.T) {
	policy := &recordingPolicy{}
	caSigner := newTestSigner(t)
	issuer := newTestIssuer(t, testDeps{
		TokenVerifier:      fixedTokenVerifier{claims: CallerClaims{Subject: "sub-123", Class: "machine"}},
		Registry:           &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}},
		Policy:             policy,
		RateLimiter:        &recordingRateLimiter{},
		Signer:             SSHSigner{Signer: caSigner},
		Audit:              &recordingAudit{},
		Clock:              fixedClock{now: time.Unix(1747000000, 0)},
		IDs:                fixedIDGenerator{id: ID{UUID: "timefix-jti", Serial: 1}},
		OperatorTTLByClass: map[string]time.Duration{"machine": time.Hour},
	})

	response, err := issuer.IssueSSHCert(context.Background(), SSHCertIssueRequest{
		AccessToken:        "access-token-123",
		DeviceID:           "prod-a012",
		PrincipalType:      PrincipalTypeTimefix,
		PublicKey:          newTestAuthorizedPublicKey(t),
		MaxLifetimeMinutes: 30,
	})
	if err != nil {
		t.Fatalf("IssueSSHCert() error = %v", err)
	}
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.SSHCert))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey(cert) error = %v", err)
	}
	cert := parsedKey.(*ssh.Certificate)
	if got, want := cert.ValidAfter, uint64(timefixCertValidAfter.Unix()); got != want {
		t.Fatalf("timefix valid after = %d, want %d (fixed window, class-independent)", got, want)
	}
	if got, want := cert.ValidBefore, uint64(timefixCertValidBefore.Unix()); got != want {
		t.Fatalf("timefix valid before = %d, want %d (fixed window, class-independent)", got, want)
	}
	if _, ok := policy.request.Context["requested_cert_ttl_minutes"]; ok {
		t.Fatalf("timefix request injected requested_cert_ttl_minutes; want none, got %v", policy.request.Context)
	}
}

// newTestIssuer wires an SSHCertIssuer from the canonical test shape:
// callers pass a flat-field tuple via testDeps so the post-LD-93 SRP
// split (PipelineDeps + Signer + OperatorTTL nesting) is hidden from the
// per-test fixture setup.
func newTestIssuer(t *testing.T, deps testDeps) *SSHCertIssuer {
	t.Helper()
	issuer, err := NewSSHCertIssuer(deps.toSSHCert())
	if err != nil {
		t.Fatalf("NewSSHCertIssuer() error = %v", err)
	}
	return issuer
}

// testDeps mirrors the flat field set callers used before the LD-93 SRP
// split. Tests build this struct; the helpers below convert into the
// post-split issuer-specific *Deps shapes.
type testDeps struct {
	TokenVerifier      TokenVerifier
	Registry           Registry
	Policy             Policy
	RateLimiter        RateLimiter
	Signer             CertSigner
	Audit              AuditSink
	Clock              Clock
	IDs                IDGenerator
	OperatorTTL        time.Duration
	OperatorTTLByClass map[string]time.Duration
}

func (d testDeps) pipeline() PipelineDeps {
	return PipelineDeps{
		TokenVerifier: d.TokenVerifier,
		Registry:      d.Registry,
		Policy:        d.Policy,
		RateLimiter:   d.RateLimiter,
		Audit:         d.Audit,
		Clock:         d.Clock,
		IDs:           d.IDs,
	}
}

func (d testDeps) toSSHCert() SSHCertIssuerDeps {
	return SSHCertIssuerDeps{
		PipelineDeps:       d.pipeline(),
		Signer:             d.Signer,
		OperatorTTL:        d.OperatorTTL,
		OperatorTTLByClass: d.OperatorTTLByClass,
	}
}

func (d testDeps) toTimePayload() TimePayloadIssuerDeps {
	return TimePayloadIssuerDeps{
		PipelineDeps: d.pipeline(),
		Signer:       d.Signer,
	}
}

// newTestTimePayloadIssuer constructs the time-payload pipeline's concrete
// type from the same flat testDeps shape; saves callers an extra helper
// for fixtures that exercise both pipelines.
func newTestTimePayloadIssuer(t *testing.T, deps testDeps) *TimePayloadIssuer {
	t.Helper()
	issuer, err := NewTimePayloadIssuer(deps.toTimePayload())
	if err != nil {
		t.Fatalf("NewTimePayloadIssuer() error = %v", err)
	}
	return issuer
}

func newTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	return signer
}

func newTestAuthorizedPublicKey(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("NewSignerFromKey() error = %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

type fixedTokenVerifier struct {
	claims CallerClaims
	err    error
}

func (v fixedTokenVerifier) VerifyAccessToken(context.Context, string) (CallerClaims, error) {
	return v.claims, v.err
}

type recordingRegistry struct {
	device DeviceRecord
	calls  int
	err    error
}

func (r *recordingRegistry) ResolveDevice(ctx context.Context, deviceID string) (DeviceRecord, error) {
	r.calls++
	return r.device, r.err
}

type recordingPolicy struct {
	request PolicyRequest
	calls   int
	err     error
}

func (p *recordingPolicy) Allow(ctx context.Context, request PolicyRequest) error {
	p.request = request
	p.calls++
	return p.err
}

type recordingRateLimiter struct {
	request RateLimitRequest
	calls   int
	err     error
}

func (l *recordingRateLimiter) Allow(ctx context.Context, request RateLimitRequest) error {
	l.request = request
	l.calls++
	return l.err
}

type recordingAudit struct {
	event  AuditEvent   // most-recent event (kept for legacy assertions)
	events []AuditEvent // every event recorded, in order
	calls  int
	err    error   // fallback error returned when errs is short
	errs   []error // per-call error sequence; entry i applies to call i+1
}

func (a *recordingAudit) Record(ctx context.Context, event AuditEvent) error {
	a.event = event
	a.events = append(a.events, event)
	a.calls++
	if len(a.errs) > 0 && a.calls <= len(a.errs) {
		return a.errs[a.calls-1]
	}
	return a.err
}

type recordingSigner struct {
	publicKey          ssh.PublicKey
	inner              ssh.Signer // when set, signs the cert for real after recording the call
	calls              int
	timePayloadCalls   int
	err                error
	timePayloadErr     error
	lastTimePayloadIn  []byte
	lastTimePayloadOut []byte
}

func (s *recordingSigner) PublicKey() ssh.PublicKey {
	return s.publicKey
}

func (s *recordingSigner) SignCert(ctx context.Context, cert *ssh.Certificate) error {
	s.calls++
	if s.err != nil {
		return s.err
	}
	if s.inner != nil {
		return cert.SignCert(rand.Reader, s.inner)
	}
	return nil
}

func (s *recordingSigner) SignTimePayload(ctx context.Context, signingInput []byte) ([]byte, error) {
	s.timePayloadCalls++
	s.lastTimePayloadIn = append([]byte(nil), signingInput...)
	if s.timePayloadErr != nil {
		return nil, s.timePayloadErr
	}
	if s.inner != nil {
		signature, err := s.inner.Sign(rand.Reader, signingInput)
		if err != nil {
			return nil, err
		}
		s.lastTimePayloadOut = append([]byte(nil), signature.Blob...)
		return signature.Blob, nil
	}
	// Default: deterministic, length-stable dummy signature so tests that
	// only care about pipeline accounting can ignore the bytes.
	s.lastTimePayloadOut = make([]byte, 64)
	return s.lastTimePayloadOut, nil
}

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

type fixedIDGenerator struct {
	id  ID
	err error
}

func (g fixedIDGenerator) NewID(time.Time) (ID, error) {
	return g.id, g.err
}
