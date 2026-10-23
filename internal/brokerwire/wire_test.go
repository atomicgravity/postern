package brokerwire

import (
	"context"
	"testing"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/atomicgravity/postern/pkg/brokerhandlers"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type stubDeps struct{}

func (stubDeps) VerifyAccessToken(context.Context, string) (broker.CallerClaims, error) {
	return broker.CallerClaims{}, nil
}
func (stubDeps) ResolveDevice(context.Context, string) (broker.DeviceRecord, error) {
	return broker.DeviceRecord{}, nil
}
func (stubDeps) Record(context.Context, broker.AuditEvent) error { return nil }

type stubAllow struct{}

func (stubAllow) Allow(context.Context, broker.PolicyRequest) error { return nil }

type stubRateLimit struct{}

func (stubRateLimit) Allow(context.Context, broker.RateLimitRequest) error { return nil }

func stubPipelineDeps() broker.PipelineDeps {
	return broker.PipelineDeps{
		TokenVerifier: stubDeps{},
		Registry:      stubDeps{},
		Policy:        stubAllow{},
		RateLimiter:   stubRateLimit{},
		Audit:         stubDeps{},
	}
}

// TestBuildTunnelIssuerEnablement locks when /ssh/tunnel is wired: an absent
// section or one with neither iot_region nor target_from_registry stays off;
// target_from_registry alone enables it without iot_region.
func TestBuildTunnelIssuerEnablement(t *testing.T) {
	cases := []struct {
		name   string
		config *brokerhandlers.TunnelingConfig
		want   bool
	}{
		{name: "absent", config: nil, want: false},
		{name: "empty section", config: &brokerhandlers.TunnelingConfig{}, want: false},
		{name: "fixed region", config: &brokerhandlers.TunnelingConfig{IOTRegion: "us-west-2"}, want: true},
		{name: "registry target", config: &brokerhandlers.TunnelingConfig{
			TargetFromRegistry: true,
			AllowedRoleARNs:    []string{"arn:aws:iam::111122223333:role/postern-tunnel"},
		}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issuer, err := buildTunnelIssuer(aws.Config{Region: "us-west-2"}, tc.config, stubPipelineDeps())
			if err != nil {
				t.Fatalf("buildTunnelIssuer() error = %v", err)
			}
			if got := issuer != nil; got != tc.want {
				t.Fatalf("issuer built = %v, want %v", got, tc.want)
			}
		})
	}
}
