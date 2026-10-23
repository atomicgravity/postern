package broker

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

const (
	testTunnelRoleARN = "arn:aws:iam::111122223333:role/postern-tunnel"
	testTunnelRegion  = "eu-central-1"
)

func newTargetTunnelIssuer(t *testing.T, deps testDeps, tun Tunneling, allowed []string) *TunnelIssuer {
	t.Helper()
	issuer, err := NewTunnelIssuer(TunnelIssuerDeps{
		PipelineDeps:       deps.pipeline(),
		Tunneling:          tun,
		TargetFromRegistry: true,
		AllowedRoleARNs:    allowed,
	})
	if err != nil {
		t.Fatalf("NewTunnelIssuer() error = %v", err)
	}
	return issuer
}

func targetDevice(attributes map[string]any) DeviceRecord {
	return DeviceRecord{Serial: "SERIAL123", FriendlyID: "prod-a012", Attributes: attributes}
}

// TestTunnelIssuerTargetFromRegistryPassesTarget locks on-mode: the role and
// region come from the device record and reach the Tunneling backend; the
// response region is whatever the backend reports.
func TestTunnelIssuerTargetFromRegistryPassesTarget(t *testing.T) {
	deps := newTunnelTestDeps(t)
	deps.Registry = &recordingRegistry{device: targetDevice(map[string]any{
		TunnelRoleARNAttribute: " " + testTunnelRoleARN + " ",
		TunnelRegionAttribute:  testTunnelRegion,
	})}
	audit := deps.Audit.(*recordingAudit)
	tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: testTunnelRegion}}
	issuer := newTargetTunnelIssuer(t, deps, tun, []string{"arn:aws:iam::111122223333:role/postern-*"})

	response, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{AccessToken: "token", DeviceID: "prod-a012"})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if tun.request.Target == nil {
		t.Fatal("Tunneling.Target = nil, want registry target")
	}
	if got, want := *tun.request.Target, (TunnelTarget{RoleARN: testTunnelRoleARN, Region: testTunnelRegion}); got != want {
		t.Fatalf("Tunneling.Target = %+v, want %+v", got, want)
	}
	if got, want := response.Region, testTunnelRegion; got != want {
		t.Fatalf("Region = %q, want %q", got, want)
	}
	if got, want := len(audit.events), 2; got != want {
		t.Fatalf("audit events = %d, want %d", got, want)
	}
}

// TestTunnelIssuerTargetOffIgnoresAttributes locks off-mode: target
// attributes on the record don't change what the backend receives.
func TestTunnelIssuerTargetOffIgnoresAttributes(t *testing.T) {
	deps := newTunnelTestDeps(t)
	deps.Registry = &recordingRegistry{device: targetDevice(map[string]any{
		TunnelRoleARNAttribute: testTunnelRoleARN,
		TunnelRegionAttribute:  testTunnelRegion,
	})}
	tun := &recordingTunneling{result: TunnelOpenResult{TunnelID: "t", SourceAccessToken: "s", Region: "us-west-2"}}
	issuer := newTestTunnelIssuer(t, deps, tun, 0)

	response, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{AccessToken: "token", DeviceID: "prod-a012"})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if tun.request.Target != nil {
		t.Fatalf("Tunneling.Target = %+v, want nil", *tun.request.Target)
	}
	if got, want := response.Region, "us-west-2"; got != want {
		t.Fatalf("Region = %q, want %q", got, want)
	}
}

// TestTunnelIssuerTargetDenials locks each registry-targeting rejection: a
// stable denied_reason, one tunnel_denied row carrying the device serial,
// and no backend call.
func TestTunnelIssuerTargetDenials(t *testing.T) {
	cases := []struct {
		name       string
		attributes map[string]any
		wantReason string
		wantStatus int
	}{
		{
			name:       "no attributes",
			attributes: nil,
			wantReason: DenyReasonTunnelTargetMissing,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "empty attribute values",
			attributes: map[string]any{TunnelRoleARNAttribute: "  ", TunnelRegionAttribute: ""},
			wantReason: DenyReasonTunnelTargetMissing,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "region only",
			attributes: map[string]any{TunnelRegionAttribute: testTunnelRegion},
			wantReason: DenyReasonTunnelTargetInvalid,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "role only",
			attributes: map[string]any{TunnelRoleARNAttribute: testTunnelRoleARN},
			wantReason: DenyReasonTunnelTargetInvalid,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "non-string role",
			attributes: map[string]any{TunnelRoleARNAttribute: int64(7), TunnelRegionAttribute: testTunnelRegion},
			wantReason: DenyReasonTunnelTargetInvalid,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "malformed role ARN",
			attributes: map[string]any{TunnelRoleARNAttribute: "arn:aws:iam::1234:user/bob", TunnelRegionAttribute: testTunnelRegion},
			wantReason: DenyReasonTunnelTargetInvalid,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "malformed region",
			attributes: map[string]any{TunnelRoleARNAttribute: testTunnelRoleARN, TunnelRegionAttribute: "Europe"},
			wantReason: DenyReasonTunnelTargetInvalid,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "role not allowed",
			attributes: map[string]any{TunnelRoleARNAttribute: "arn:aws:iam::999988887777:role/other", TunnelRegionAttribute: testTunnelRegion},
			wantReason: DenyReasonTunnelRoleNotAllowed,
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := newTunnelTestDeps(t)
			deps.Registry = &recordingRegistry{device: targetDevice(tc.attributes)}
			audit := deps.Audit.(*recordingAudit)
			tun := &recordingTunneling{}
			issuer := newTargetTunnelIssuer(t, deps, tun, []string{testTunnelRoleARN})

			_, err := issuer.OpenTunnel(context.Background(), TunnelOpenRequest{AccessToken: "token", DeviceID: "prod-a012"})
			var domainErr Error
			if !errors.As(err, &domainErr) {
				t.Fatalf("error = %v, want broker.Error", err)
			}
			if got, want := domainErr.StatusCode, tc.wantStatus; got != want {
				t.Fatalf("status = %d, want %d", got, want)
			}
			if tun.calls != 0 {
				t.Fatalf("Tunneling.OpenTunnel calls = %d, want 0", tun.calls)
			}
			if got, want := len(audit.events), 1; got != want {
				t.Fatalf("audit events = %d, want %d", got, want)
			}
			event := audit.events[0]
			if got, want := event.Event, EventTunnelDenied; got != want {
				t.Fatalf("event = %q, want %q", got, want)
			}
			if got, want := event.DeniedReason, tc.wantReason; got != want {
				t.Fatalf("denied_reason = %q, want %q", got, want)
			}
			if got, want := event.DeviceSerial, "SERIAL123"; got != want {
				t.Fatalf("device_serial = %q, want %q", got, want)
			}
			if got, want := event.EngineerSub, "sub-123"; got != want {
				t.Fatalf("engineer_sub = %q, want %q", got, want)
			}
		})
	}
}

// TestTunnelIssuerTargetCheckedAfterPolicy locks the ordering: a Policy
// deny wins over a missing target.
func TestTunnelIssuerTargetCheckedAfterPolicy(t *testing.T) {
	deps := newTunnelTestDeps(t)
	deps.Registry = &recordingRegistry{device: targetDevice(nil)}
	deps.Policy = &recordingPolicy{err: Error{StatusCode: http.StatusForbidden, Message: "denied"}}
	audit := deps.Audit.(*recordingAudit)
	issuer := newTargetTunnelIssuer(t, deps, &recordingTunneling{}, []string{testTunnelRoleARN})

	_, _ = issuer.OpenTunnel(context.Background(), TunnelOpenRequest{AccessToken: "token", DeviceID: "prod-a012"})
	if got, want := audit.events[len(audit.events)-1].DeniedReason, DenyReasonAuthorizationDenied; got != want {
		t.Fatalf("denied_reason = %q, want %q", got, want)
	}
}

func TestNewTunnelIssuerValidatesAllowedRoleARNsWithTarget(t *testing.T) {
	deps := newTunnelTestDeps(t)
	cases := []struct {
		allowed []string
		want    error
	}{
		{nil, ErrTunnelingAllowedRoleARNsRequired},
		{[]string{}, ErrTunnelingAllowedRoleARNsRequired},
		{[]string{""}, ErrTunnelingAllowedRoleARNInvalid},
		{[]string{testTunnelRoleARN, "arn:aws:iam::*:role/postern-tunnel"}, ErrTunnelingAllowedRoleARNInvalid},
	}
	for _, tc := range cases {
		_, err := NewTunnelIssuer(TunnelIssuerDeps{
			PipelineDeps:       deps.pipeline(),
			Tunneling:          &recordingTunneling{},
			TargetFromRegistry: true,
			AllowedRoleARNs:    tc.allowed,
		})
		if !errors.Is(err, tc.want) {
			t.Fatalf("NewTunnelIssuer(allowed=%q) error = %v, want %v", tc.allowed, err, tc.want)
		}
	}
}

// TestValidAllowedRoleARN locks the allowlist entry shape: a wildcard can
// never reach the account field, and `,` / `?` are rejected because the env
// var is comma-joined and globMatch has no `?`.
func TestValidAllowedRoleARN(t *testing.T) {
	for _, entry := range []string{
		testTunnelRoleARN,
		"arn:aws:iam::111122223333:role/*",
		"arn:aws:iam::111122223333:role/path/postern-*",
		"arn:aws:iam::111122223333:role/a+b=c.d@e_f-g",
	} {
		if !ValidAllowedRoleARN(entry) {
			t.Errorf("ValidAllowedRoleARN(%q) = false, want true", entry)
		}
	}
	for _, entry := range []string{
		"",
		"*",
		"arn:*",
		"arn:aws:iam::*:role/*",
		"arn:aws:iam::*:role/postern-tunnel",
		"arn:aws:iam::1111*:role/x",
		"arn:aws:iam::111122223333:*",
		"arn:aws:iam::111122223333:role/",
		"arn:aws:iam::111122223333:user/bob",
		"arn:aws:iam::111122223333:role/tunnel,eu",
		"arn:aws:iam::111122223333:role/tunnel-?",
		"arn:aws-cn:iam::111122223333:role/x",
		"arn:aws-us-gov:iam::111122223333:role/x",
	} {
		if ValidAllowedRoleARN(entry) {
			t.Errorf("ValidAllowedRoleARN(%q) = true, want false", entry)
		}
	}
}

func TestRoleARNAllowed(t *testing.T) {
	cases := []struct {
		pattern string
		arn     string
		want    bool
	}{
		{testTunnelRoleARN, testTunnelRoleARN, true},
		{testTunnelRoleARN, testTunnelRoleARN + "x", false},
		{"arn:aws:iam::*:role/postern-tunnel", "arn:aws:iam::444455556666:role/postern-tunnel", true},
		{"arn:aws:iam::*:role/postern-tunnel", "arn:aws:iam::444455556666:role/postern-tunnel-admin", false},
		{"arn:aws:iam::111122223333:role/*", "arn:aws:iam::111122223333:role/path/deep", true},
		{"arn:aws:iam::111122223333:role/*", "arn:aws:iam::999988887777:role/x", false},
		{"arn:aws:iam::*:role/*-tunnel", "arn:aws:iam::111122223333:role/a-b-tunnel", true},
		{"*", "arn:aws:iam::111122223333:role/x", true},
		{"arn:aws:iam::*:role/a*b*c", "arn:aws:iam::1:role/aXbYbZc", true},
		{"arn:aws:iam::*:role/a*b*c", "arn:aws:iam::1:role/aXbYcZ", false},
	}
	for _, tc := range cases {
		if got := roleARNAllowed(tc.arn, []string{tc.pattern}); got != tc.want {
			t.Errorf("roleARNAllowed(%q, [%q]) = %v, want %v", tc.arn, tc.pattern, got, tc.want)
		}
	}
}

func TestTunnelTargetPatterns(t *testing.T) {
	for _, arn := range []string{
		testTunnelRoleARN,
		"arn:aws:iam::111122223333:role/path/name",
		"arn:aws:iam::111122223333:role/a+b=c,d.e@f_g-h",
	} {
		if !tunnelRoleARNPattern.MatchString(arn) {
			t.Errorf("role ARN %q rejected", arn)
		}
	}
	for _, arn := range []string{
		"arn:aws-us-gov:iam::111122223333:role/path/name",
		"arn:aws-cn:iam::111122223333:role/x",
		"arn:aws:iam::111122223333:user/bob",
		"arn:aws:iam::11112222333:role/x",
		"arn:aws:sts::111122223333:assumed-role/x/y",
		"arn:aws:iam::111122223333:role/",
	} {
		if tunnelRoleARNPattern.MatchString(arn) {
			t.Errorf("role ARN %q accepted", arn)
		}
	}
	for _, region := range []string{"us-east-1", "ap-southeast-2", "eu-central-1", "il-central-1"} {
		if !validTunnelRegion(region) {
			t.Errorf("region %q rejected", region)
		}
	}
	for _, region := range []string{"", "us-east", "US-EAST-1", "us-east-1a", "https://iot.us-east-1", "us-gov-west-1", "cn-north-1", "us-iso-east-1", "us-isob-east-1", "eusc-de-east-1"} {
		if validTunnelRegion(region) {
			t.Errorf("region %q accepted", region)
		}
	}
}
