package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// recordingTunneling is the test stub for the Tunneling abstraction; it
// captures the per-call request the broker pipeline composes and returns a
// configurable result/error pair. The kindErr variant lets a test simulate
// the AWS LimitExceededException → tunnel_limit_exceeded mapping without
// pulling the AWS SDK error types into the broker test package.
type recordingTunneling struct {
	result  TunnelOpenResult
	err     error
	calls   int
	request TunnelOpenInternal
}

func (t *recordingTunneling) OpenTunnel(_ context.Context, request TunnelOpenInternal) (TunnelOpenResult, error) {
	t.calls++
	t.request = request
	return t.result, t.err
}

// classifiedTunnelingErr is the test-side equivalent of internal/tunneling's
// wrapped error: it satisfies broker.TunnelingErrorClassifier so the
// pipeline's deny-reason mapping treats it as either tunnel_limit_exceeded
// or tunneling_unavailable.
type classifiedTunnelingErr struct {
	kind TunnelingErrorKind
	msg  string
}

func (e classifiedTunnelingErr) Error() string                          { return e.msg }
func (e classifiedTunnelingErr) TunnelingErrorKind() TunnelingErrorKind { return e.kind }

func newTunnelTestDeps(t *testing.T) testDeps {
	t.Helper()
	return testDeps{
		TokenVerifier: fixedTokenVerifier{claims: EngineerClaims{
			Subject: "sub-123",
			Email:   "engineer@example.com",
			Groups:  []string{"postern-engineers"},
		}},
		Registry:    &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123", FriendlyID: "prod-a012"}},
		Policy:      &recordingPolicy{},
		RateLimiter: &recordingRateLimiter{},
		Audit:       &recordingAudit{},
		Clock:       fixedClock{now: time.Unix(1747000000, 0)},
		IDs:         fixedIDGenerator{id: ID{UUID: "tunnel-jti", Serial: 42}},
	}
}

func newTestTunnelIssuer(t *testing.T, deps testDeps, tun Tunneling, defaultLifetime int32) *TunnelIssuer {
	t.Helper()
	issuer, err := NewTunnelIssuer(TunnelIssuerDeps{
		PipelineDeps:              deps.pipeline(),
		Tunneling:                 tun,
		DefaultMaxLifetimeMinutes: defaultLifetime,
	})
	if err != nil {
		t.Fatalf("NewTunnelIssuer() error = %v", err)
	}
	return issuer
}

// TestTunnelIssuerHappyPath locks the success path: registry + policy +
// AWS call → authorized + issued audit pair joined on jti; response carries
// the AWS-side source access token + tunnel id + region + resolved TTL.
func TestTunnelIssuerHappyPath(t *testing.T) {
	deps := newTunnelTestDeps(t)
	audit := deps.Audit.(*recordingAudit)
	tun := &recordingTunneling{result: TunnelOpenResult{
		TunnelID:          "tun-abc-123",
		SourceAccessToken: "source-token-xyz",
		Region:            "us-west-2",
	}}
	issuer := newTestTunnelIssuer(t, deps, tun, 0)

	response, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken: "access-token-123",
		DeviceID:    "prod-a012",
		UserAgent:   "postern/test",
		RemoteAddr:  "203.0.113.1:12345",
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if got, want := response.TunnelID, "tun-abc-123"; got != want {
		t.Fatalf("TunnelID = %q, want %q", got, want)
	}
	if got, want := response.SourceAccessToken, "source-token-xyz"; got != want {
		t.Fatalf("SourceAccessToken = %q, want %q", got, want)
	}
	if got, want := response.Region, "us-west-2"; got != want {
		t.Fatalf("Region = %q, want %q", got, want)
	}
	if got, want := response.MaxLifetimeMinutes, DefaultTunnelLifetimeMinutes; got != want {
		t.Fatalf("MaxLifetimeMinutes = %d, want %d (broker default)", got, want)
	}
	if tun.calls != 1 {
		t.Fatalf("Tunneling.OpenTunnel calls = %d, want 1", tun.calls)
	}
	if got, want := tun.request.ThingName, "device-SERIAL123"; got != want {
		t.Fatalf("Tunneling.ThingName = %q, want %q", got, want)
	}
	if got, want := tun.request.Services, []string{"SSH"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("Tunneling.Services = %v, want %v", got, want)
	}
	if got, want := tun.request.MaxLifetimeMinutes, DefaultTunnelLifetimeMinutes; got != want {
		t.Fatalf("Tunneling.MaxLifetimeMinutes = %d, want %d", got, want)
	}
	// Audit invariant: two events on happy path — authorized + issued —
	// joined on jti, both carrying ModeTunnel as PrincipalType.
	if got, want := audit.calls, 2; got != want {
		t.Fatalf("audit calls = %d, want %d", got, want)
	}
	if got, want := audit.events[0].Event, EventTunnelAuthorized; got != want {
		t.Fatalf("audit[0] = %q, want %q", got, want)
	}
	if got, want := audit.events[1].Event, EventTunnelIssued; got != want {
		t.Fatalf("audit[1] = %q, want %q", got, want)
	}
	if audit.events[0].JTI != audit.events[1].JTI {
		t.Fatalf("authorized.jti = %q, issued.jti = %q (must match)", audit.events[0].JTI, audit.events[1].JTI)
	}
	for _, ev := range audit.events {
		if ev.PrincipalType != ModeTunnel {
			t.Fatalf("event %q PrincipalType = %q, want %q", ev.Event, ev.PrincipalType, ModeTunnel)
		}
	}
}

// TestTunnelIssuerHonorsEngineerRequestedTTL locks engineer-driven TTL: an
// explicit max_lifetime_minutes value flows through to the AWS call and is
// echoed on the response. Capped at the 12-hour AWS ceiling.
func TestTunnelIssuerHonorsEngineerRequestedTTL(t *testing.T) {
	deps := newTunnelTestDeps(t)
	tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "r"}}
	issuer := newTestTunnelIssuer(t, deps, tun, 0)

	response, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken:        "access-token-123",
		DeviceID:           "prod-a012",
		MaxLifetimeMinutes: 240,
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if got, want := response.MaxLifetimeMinutes, int32(240); got != want {
		t.Fatalf("response.MaxLifetimeMinutes = %d, want %d", got, want)
	}
	if got, want := tun.request.MaxLifetimeMinutes, int32(240); got != want {
		t.Fatalf("AWS request.MaxLifetimeMinutes = %d, want %d", got, want)
	}
}

// TestTunnelIssuerRejectsOverCeilingTTL locks the broker-side TTL clamp.
// AWS would also reject, but surfacing it here saves an AWS-credentialed
// round-trip and emits a stable denied_reason literal.
func TestTunnelIssuerRejectsOverCeilingTTL(t *testing.T) {
	deps := newTunnelTestDeps(t)
	audit := deps.Audit.(*recordingAudit)
	tun := &recordingTunneling{}
	issuer := newTestTunnelIssuer(t, deps, tun, 0)

	_, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken:        "access-token-123",
		DeviceID:           "prod-a012",
		MaxLifetimeMinutes: 13 * 60, // 13h > 12h AWS ceiling
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("OpenTunnel() error = %v, want 400 broker.Error", err)
	}
	if tun.calls != 0 {
		t.Fatalf("Tunneling.OpenTunnel calls = %d, want 0 (request must reject before AWS call)", tun.calls)
	}
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	if got := audit.events[0].DeniedReason; got != DenyReasonMaxLifetimeExceedsCeiling {
		t.Fatalf("denied_reason = %q, want %q", got, DenyReasonMaxLifetimeExceedsCeiling)
	}
}

// TestTunnelIssuerPipelineFailureModes locks each pre-AWS denial path's
// denied_reason and audit-row count. Mirrors the cert-mint and time-payload
// failure-modes tables.
func TestTunnelIssuerPipelineFailureModes(t *testing.T) {
	cases := []struct {
		name           string
		mutate         func(*TunnelOpenRequest)
		verifierErr    error
		registryErr    error
		policyErr      error
		rateLimiterErr error
		tunnelingErr   error
		auditErr       error
		wantStatus     int
		wantDenyReason string
		wantWrappedSub string
		wantAWSCalls   int
		wantAuditCalls int
		wantEventOrder []string
	}{
		{
			name:           "invalid access token",
			verifierErr:    errors.New("token signature invalid"),
			wantStatus:     http.StatusUnauthorized,
			wantDenyReason: DenyReasonInvalidAccessToken,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTunnelDenied},
		},
		{
			name:           "rate limit exceeded short-circuits before registry",
			rateLimiterErr: Error{StatusCode: http.StatusTooManyRequests, Message: "rate limit"},
			wantStatus:     http.StatusTooManyRequests,
			wantDenyReason: DenyReasonRateLimitExceeded,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTunnelDenied},
		},
		{
			name:           "missing device_id after trim",
			mutate:         func(r *TunnelOpenRequest) { r.DeviceID = "   " },
			wantStatus:     http.StatusBadRequest,
			wantDenyReason: DenyReasonMissingDeviceID,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTunnelDenied},
		},
		{
			name:           "device not found",
			registryErr:    Error{StatusCode: http.StatusNotFound, Message: "device not found"},
			wantStatus:     http.StatusNotFound,
			wantDenyReason: DenyReasonDeviceNotFound,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTunnelDenied},
		},
		{
			name:           "authorization denied",
			policyErr:      Error{StatusCode: http.StatusForbidden, Message: "denied"},
			wantStatus:     http.StatusForbidden,
			wantDenyReason: DenyReasonAuthorizationDenied,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTunnelDenied},
		},
		{
			name:           "policy unavailable",
			policyErr:      Error{StatusCode: http.StatusBadGateway, Message: "AVP down"},
			wantStatus:     http.StatusBadGateway,
			wantDenyReason: DenyReasonPolicyUnavailable,
			wantAuditCalls: 1,
			wantEventOrder: []string{EventTunnelDenied},
		},
		{
			name:           "pre-aws audit failure short-circuits before AWS call",
			auditErr:       errors.New("cloudwatch down"),
			wantWrappedSub: "record tunnel audit event: cloudwatch down",
			wantAWSCalls:   0,
			wantAuditCalls: 1,
		},
		{
			name:           "AWS limit exceeded → tunnel_limit_exceeded + 429",
			tunnelingErr:   classifiedTunnelingErr{kind: TunnelingErrorLimitExceeded, msg: "quota"},
			wantStatus:     http.StatusTooManyRequests,
			wantDenyReason: DenyReasonTunnelLimitExceeded,
			wantAWSCalls:   1,
			wantAuditCalls: 2,
			wantEventOrder: []string{EventTunnelAuthorized, EventTunnelDenied},
		},
		{
			name:           "AWS generic failure → tunneling_unavailable + 503",
			tunnelingErr:   classifiedTunnelingErr{kind: TunnelingErrorUnknown, msg: "service unavailable"},
			wantStatus:     http.StatusServiceUnavailable,
			wantDenyReason: DenyReasonTunnelingUnavailable,
			wantAWSCalls:   1,
			wantAuditCalls: 2,
			wantEventOrder: []string{EventTunnelAuthorized, EventTunnelDenied},
		},
		{
			name:           "AWS non-classifier error → tunneling_unavailable + 503",
			tunnelingErr:   errors.New("plain error"),
			wantStatus:     http.StatusServiceUnavailable,
			wantDenyReason: DenyReasonTunnelingUnavailable,
			wantAWSCalls:   1,
			wantAuditCalls: 2,
			wantEventOrder: []string{EventTunnelAuthorized, EventTunnelDenied},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := newTunnelTestDeps(t)
			deps.TokenVerifier = fixedTokenVerifier{
				claims: EngineerClaims{Subject: "sub-123"},
				err:    tc.verifierErr,
			}
			deps.Registry = &recordingRegistry{device: DeviceRecord{Serial: "SERIAL123"}, err: tc.registryErr}
			deps.Policy = &recordingPolicy{err: tc.policyErr}
			deps.RateLimiter = &recordingRateLimiter{err: tc.rateLimiterErr}
			audit := &recordingAudit{err: tc.auditErr}
			deps.Audit = audit
			tun := &recordingTunneling{
				result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "r"},
				err:    tc.tunnelingErr,
			}
			issuer := newTestTunnelIssuer(t, deps, tun, 0)

			request := TunnelOpenRequest{
				AccessToken: "good-token",
				DeviceID:    "prod-a012",
			}
			if tc.mutate != nil {
				tc.mutate(&request)
			}

			_, err := issuer.OpenTunnel(context.Background(), request)
			if err == nil {
				t.Fatalf("OpenTunnel() returned nil error, want failure")
			}
			if tc.wantStatus != 0 {
				var domainErr Error
				if !errors.As(err, &domainErr) {
					t.Fatalf("error = %v, want broker.Error", err)
				}
				if got, want := domainErr.StatusCode, tc.wantStatus; got != want {
					t.Fatalf("status = %d, want %d", got, want)
				}
			}
			if tc.wantWrappedSub != "" {
				wrapped := err.Error()
				if wrapped == "" || !errStringContains(wrapped, tc.wantWrappedSub) {
					t.Fatalf("error = %v, want contains %q", err, tc.wantWrappedSub)
				}
			}
			if got, want := tun.calls, tc.wantAWSCalls; got != want {
				t.Fatalf("Tunneling.OpenTunnel calls = %d, want %d", got, want)
			}
			if got, want := audit.calls, tc.wantAuditCalls; got != want {
				t.Fatalf("audit calls = %d, want %d", got, want)
			}
			if tc.wantDenyReason != "" {
				// The denied event is the last one — authorized comes
				// first on AWS-call-failure paths, the deny path's
				// single event for every other case.
				if len(audit.events) == 0 {
					t.Fatalf("no audit events; want one with denied_reason %q", tc.wantDenyReason)
				}
				denyEvent := audit.events[len(audit.events)-1]
				if got := denyEvent.DeniedReason; got != tc.wantDenyReason {
					t.Fatalf("denied_reason = %q, want %q", got, tc.wantDenyReason)
				}
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

// TestTunnelIssuerEmitsBrokerConfiguredDefaultTTL locks the operator-config
// fallback: when the engineer omits max_lifetime_minutes, the broker uses
// the value passed to NewTunnelIssuer.
func TestTunnelIssuerEmitsBrokerConfiguredDefaultTTL(t *testing.T) {
	deps := newTunnelTestDeps(t)
	tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "r"}}
	issuer := newTestTunnelIssuer(t, deps, tun, 60) // operator default: 1 hour

	response, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken: "access-token-123",
		DeviceID:    "prod-a012",
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if got, want := response.MaxLifetimeMinutes, int32(60); got != want {
		t.Fatalf("MaxLifetimeMinutes = %d, want %d (operator-configured default)", got, want)
	}
	if got, want := tun.request.MaxLifetimeMinutes, int32(60); got != want {
		t.Fatalf("AWS request.MaxLifetimeMinutes = %d, want %d", got, want)
	}
}

// TestTunnelIssuerInjectsPolicyContextLifetime locks the Cedar-context
// plumbing: the engineer-requested max_lifetime_minutes flows into Policy
// Request.Context so operators can author per-fleet TTL ceilings via
// Cedar `when` clauses.
func TestTunnelIssuerInjectsPolicyContextLifetime(t *testing.T) {
	deps := newTunnelTestDeps(t)
	policy := &recordingPolicy{}
	deps.Policy = policy
	tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "r"}}
	issuer := newTestTunnelIssuer(t, deps, tun, 0)

	_, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken:        "access-token-123",
		DeviceID:           "prod-a012",
		MaxLifetimeMinutes: 120,
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if got, want := policy.request.Mode, ModeTunnel; got != want {
		t.Fatalf("policy.Mode = %q, want %q", got, want)
	}
	got, ok := policy.request.Context["requested_max_lifetime_minutes"]
	if !ok {
		t.Fatalf("policy.Context missing requested_max_lifetime_minutes; got %v", policy.request.Context)
	}
	if want := int64(120); got != want {
		t.Fatalf("policy.Context[requested_max_lifetime_minutes] = %v, want %v", got, want)
	}
}

// TestTunnelIssuerPolicyContextLifetimeUsesResolvedDefault pins F-TN-A-3:
// when the engineer omits --max-lifetime (MaxLifetimeMinutes == 0), the
// PolicyContext value passed to Cedar must be the resolved post-default
// value, NOT zero. Injecting zero would let an engineer bypass per-fleet
// Cedar `when context.requested_max_lifetime_minutes <= N` ceilings by
// simply omitting the flag — zero satisfies the predicate.
func TestTunnelIssuerPolicyContextLifetimeUsesResolvedDefault(t *testing.T) {
	deps := newTunnelTestDeps(t)
	policy := &recordingPolicy{}
	deps.Policy = policy
	tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "r"}}
	issuer := newTestTunnelIssuer(t, deps, tun, 90) // operator default: 90 minutes

	_, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken:        "access-token-123",
		DeviceID:           "prod-a012",
		MaxLifetimeMinutes: 0, // engineer omitted --max-lifetime
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	got, ok := policy.request.Context["requested_max_lifetime_minutes"]
	if !ok {
		t.Fatalf("policy.Context missing requested_max_lifetime_minutes; got %v", policy.request.Context)
	}
	if want := int64(90); got != want {
		t.Fatalf("policy.Context[requested_max_lifetime_minutes] = %v, want %v (resolved default, not engineer's zero)", got, want)
	}
}

// TestTunnelIssuerPostAWSAuditFailureBestEffort locks the post-AWS-call
// best-effort contract: if the issued audit row fails to record, the
// source access token still returns to the engineer (the tunnel is
// already provisioned at AWS). Operators detect missing rows by joining
// authorized vs issued on jti.
func TestTunnelIssuerPostAWSAuditFailureBestEffort(t *testing.T) {
	deps := newTunnelTestDeps(t)
	audit := &recordingAudit{errs: []error{nil, errors.New("cloudwatch flake")}}
	deps.Audit = audit
	tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "r"}}
	issuer := newTestTunnelIssuer(t, deps, tun, 0)

	response, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken: "access-token-123",
		DeviceID:    "prod-a012",
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v, want nil (post-AWS audit is best-effort)", err)
	}
	if response.SourceAccessToken == "" {
		t.Fatalf("response.SourceAccessToken empty")
	}
	if audit.calls != 2 {
		t.Fatalf("audit calls = %d, want 2", audit.calls)
	}
}

// TestTunnelIssuerSkipsRegistryOnRateLimitDenial mirrors F-BROKER-1 for
// /ssh/tunnel: a rate-limited request must NOT reach Registry, closing
// the authenticated device-enumeration oracle on this endpoint too.
func TestTunnelIssuerSkipsRegistryOnRateLimitDenial(t *testing.T) {
	deps := newTunnelTestDeps(t)
	registry := &recordingRegistry{device: DeviceRecord{Serial: "should-not-be-resolved"}}
	deps.Registry = registry
	deps.RateLimiter = &recordingRateLimiter{err: Error{StatusCode: http.StatusTooManyRequests, Message: "rate limit exceeded"}}
	tun := &recordingTunneling{}
	issuer := newTestTunnelIssuer(t, deps, tun, 0)

	_, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken: "good-token",
		DeviceID:    "prod-a012",
	})
	var domainErr Error
	if !errors.As(err, &domainErr) || domainErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("OpenTunnel() error = %v, want 429 broker.Error", err)
	}
	if registry.calls != 0 {
		t.Fatalf("registry.ResolveDevice calls = %d, want 0 (rate-limit must short-circuit before registry)", registry.calls)
	}
}

// TestRecordTunnelHandlerDenialEmitsTunnelDeniedEvent locks the handler-
// side pre-invocation audit path: missing-bearer / malformed-body produce
// a tunnel_denied row (not ssh_cert_denied or time_payload_denied) so
// operators can filter by endpoint without joining audit rows to URLs.
func TestRecordTunnelHandlerDenialEmitsTunnelDeniedEvent(t *testing.T) {
	deps := newTunnelTestDeps(t)
	audit := &recordingAudit{}
	deps.Audit = audit
	deps.IDs = fixedIDGenerator{id: ID{UUID: "handler-tunnel-jti", Serial: 1}}
	issuer := newTestTunnelIssuer(t, deps, &recordingTunneling{}, 0)

	issuer.RecordTunnelHandlerDenial(context.Background(), HandlerDenial{
		DeniedReason: DenyReasonMissingBearerToken,
		SourceIP:     "203.0.113.5",
		UserAgent:    "postern/test",
	})

	if got, want := audit.calls, 1; got != want {
		t.Fatalf("audit calls = %d, want %d", got, want)
	}
	got := audit.events[0]
	if got.Event != EventTunnelDenied {
		t.Fatalf("event = %q, want %q", got.Event, EventTunnelDenied)
	}
	if got.DeniedReason != DenyReasonMissingBearerToken {
		t.Fatalf("denied_reason = %q, want %q", got.DeniedReason, DenyReasonMissingBearerToken)
	}
	if got.PrincipalType != ModeTunnel {
		t.Fatalf("principal_type = %q, want %q", got.PrincipalType, ModeTunnel)
	}
	if got.JTI != "handler-tunnel-jti" {
		t.Fatalf("jti = %q, want %q", got.JTI, "handler-tunnel-jti")
	}
}

// TestNewTunnelIssuerRejectsMissingDeps locks the constructor validation:
// every Err* sentinel is reachable via errors.Is on the joined return.
func TestNewTunnelIssuerRejectsMissingDeps(t *testing.T) {
	_, err := NewTunnelIssuer(TunnelIssuerDeps{})
	if err == nil {
		t.Fatal("NewTunnelIssuer({}) returned nil error")
	}
	for _, sentinel := range []error{
		ErrTokenVerifierRequired,
		ErrRegistryRequired,
		ErrPolicyRequired,
		ErrRateLimiterRequired,
		ErrAuditRequired,
		ErrTunnelingRequired,
	} {
		if !errors.Is(err, sentinel) {
			t.Errorf("errors.Is(err, %v) = false, want true", sentinel)
		}
	}
}

// TestTunnelIssuerAppliesThingNameFormat locks the configurable thing-name
// substitution: each operator-supplied format flows into the AWS-side
// OpenTunnel call with {serial} replaced by the registry-resolved hardware
// serial.
func TestTunnelIssuerAppliesThingNameFormat(t *testing.T) {
	cases := []struct {
		name          string
		format        string
		serial        string
		wantThingName string
	}{
		{name: "default device-prefix", format: "device-{serial}", serial: "SERIAL123", wantThingName: "device-SERIAL123"},
		{name: "serial only", format: "{serial}", serial: "SN42", wantThingName: "SN42"},
		{name: "prefix and suffix", format: "fleet-{serial}-prod", serial: "X9", wantThingName: "fleet-X9-prod"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := newTunnelTestDeps(t)
			deps.Registry = &recordingRegistry{device: DeviceRecord{Serial: tc.serial, FriendlyID: "prod-a012"}}
			tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "r"}}
			issuer, err := NewTunnelIssuer(TunnelIssuerDeps{
				PipelineDeps:    deps.pipeline(),
				Tunneling:       tun,
				ThingNameFormat: tc.format,
			})
			if err != nil {
				t.Fatalf("NewTunnelIssuer() error = %v", err)
			}

			_, err = issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
				AccessToken: "access-token",
				DeviceID:    "prod-a012",
			})
			if err != nil {
				t.Fatalf("OpenTunnel() error = %v", err)
			}
			if got := tun.request.ThingName; got != tc.wantThingName {
				t.Fatalf("Tunneling.ThingName = %q, want %q", got, tc.wantThingName)
			}
		})
	}
}

// TestNewTunnelIssuerDefaultsEmptyThingNameFormat pins the
// wrapper-friendliness path: deps with ThingNameFormat == "" don't fail
// at construction — the constructor substitutes "device-{serial}" so
// the historical convention keeps working when a wrapper neglects to
// set the field. (Config-layer validation already covers operator
// misconfiguration; this branch protects against direct dep injection.)
func TestNewTunnelIssuerDefaultsEmptyThingNameFormat(t *testing.T) {
	deps := newTunnelTestDeps(t)
	tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "r"}}
	issuer, err := NewTunnelIssuer(TunnelIssuerDeps{
		PipelineDeps:    deps.pipeline(),
		Tunneling:       tun,
		ThingNameFormat: "",
	})
	if err != nil {
		t.Fatalf("NewTunnelIssuer() error = %v", err)
	}

	_, err = issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken: "access-token",
		DeviceID:    "prod-a012",
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if got, want := tun.request.ThingName, "device-SERIAL123"; got != want {
		t.Fatalf("Tunneling.ThingName = %q, want %q (empty format must fall back to historical convention)", got, want)
	}
}

// TestNewTunnelIssuerRejectsMalformedThingNameFormat pins the
// defense-in-depth constructor validation: a format without exactly one
// {serial} placeholder fails construction, so wrapper-injected configs
// that bypass the YAML loader can't silently break OpenTunnel calls at
// runtime.
func TestNewTunnelIssuerRejectsMalformedThingNameFormat(t *testing.T) {
	cases := []struct {
		name   string
		format string
	}{
		{name: "no placeholder", format: "static-thing-name"},
		{name: "two placeholders", format: "{serial}-{serial}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := newTunnelTestDeps(t)
			_, err := NewTunnelIssuer(TunnelIssuerDeps{
				PipelineDeps:    deps.pipeline(),
				Tunneling:       &recordingTunneling{},
				ThingNameFormat: tc.format,
			})
			if err == nil {
				t.Fatalf("NewTunnelIssuer() returned nil error for format %q", tc.format)
			}
			if !errors.Is(err, ErrTunnelingThingNameFormatInvalid) {
				t.Fatalf("NewTunnelIssuer() error = %v, want ErrTunnelingThingNameFormatInvalid", err)
			}
		})
	}
}

// TestNewTunnelIssuerClampsDefaultLifetime locks the constructor's
// default-TTL guard: a configured default above the AWS ceiling is
// silently clamped to 720 minutes (12 hours).
func TestNewTunnelIssuerClampsDefaultLifetime(t *testing.T) {
	deps := newTunnelTestDeps(t)
	tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "r"}}
	issuer := newTestTunnelIssuer(t, deps, tun, MaxTunnelLifetimeMinutes+100)

	response, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{
		AccessToken: "access-token-123",
		DeviceID:    "prod-a012",
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if got, want := response.MaxLifetimeMinutes, MaxTunnelLifetimeMinutes; got != want {
		t.Fatalf("MaxLifetimeMinutes = %d, want %d (over-ceiling default clamps)", got, want)
	}
}

// TestTunnelingErrorClassifierSurvivesErrorWrapping pins F-TN-A-4: both
// tunnelingDenyReason and mapTunnelingError must route through
// errors.As so a future wrapper between the AWS impl and the broker
// call site that does fmt.Errorf("openTunnel: %w", err) doesn't lose
// the classifier interface. A direct type assertion would silently
// downgrade a tunnel_limit_exceeded / 429 to tunneling_unavailable / 503.
func TestTunnelingErrorClassifierSurvivesErrorWrapping(t *testing.T) {
	classifier := classifiedTunnelingErr{kind: TunnelingErrorLimitExceeded, msg: "quota"}
	wrapped := fmt.Errorf("openTunnel: %w", classifier)

	if got, want := tunnelingDenyReason(wrapped), DenyReasonTunnelLimitExceeded; got != want {
		t.Fatalf("tunnelingDenyReason(wrapped) = %q, want %q", got, want)
	}

	mapped := mapTunnelingError(wrapped)
	var domainErr Error
	if !errors.As(mapped, &domainErr) {
		t.Fatalf("mapTunnelingError(wrapped) = %v, want broker.Error", mapped)
	}
	if got, want := domainErr.StatusCode, http.StatusTooManyRequests; got != want {
		t.Fatalf("status = %d, want %d (classifier must survive %%w wrapping)", got, want)
	}
}

// errStringContains is a thin helper so the failure-modes table can assert
// substring matches without pulling in strings.Contains at every call site.
func errStringContains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
