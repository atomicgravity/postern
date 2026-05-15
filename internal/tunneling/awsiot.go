// Package tunneling is the broker's Tunneling impl: AWS IoT Secure
// Tunneling, wrapping the SDK's OpenTunnel. The destination side receives
// its access token via AWS IoT MQTT directly — the broker is not in that
// data path.
package tunneling

import (
	"context"
	"errors"
	"fmt"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iotsecuretunneling"
	"github.com/aws/aws-sdk-go-v2/service/iotsecuretunneling/types"
)

// ErrTunnelingRegionRequired is returned when the region is empty. The CLI
// uses the response region to dial the AWS data-tunneling WebSocket.
var ErrTunnelingRegionRequired = errors.New("tunneling AWS region is required")

// AWSIoTClient is the subset of the iotsecuretunneling API the impl consumes.
// The broker has no v1 use case for CloseTunnel / RotateTunnelAccessToken /
// DescribeTunnel — engineer ^C closes from the source-proxy side, and AWS
// ages tunnels at their configured TTL.
type AWSIoTClient interface {
	OpenTunnel(context.Context, *iotsecuretunneling.OpenTunnelInput, ...func(*iotsecuretunneling.Options)) (*iotsecuretunneling.OpenTunnelOutput, error)
}

// AWSIoTTunneling is the broker's Tunneling impl. Each OpenTunnel call
// translates broker.TunnelOpenInternal into one iotsecuretunneling RPC.
type AWSIoTTunneling struct {
	client AWSIoTClient
	region string
}

// NewAWSIoTTunneling constructs against an existing AWS client.
func NewAWSIoTTunneling(client AWSIoTClient, region string) (*AWSIoTTunneling, error) {
	if region == "" {
		return nil, ErrTunnelingRegionRequired
	}
	return &AWSIoTTunneling{client: client, region: region}, nil
}

// NewAWSIoTTunnelingFromConfig wires the iotsecuretunneling client from an
// aws.Config. region pins the SDK endpoint and flows into every
// TunnelOpenResult.
func NewAWSIoTTunnelingFromConfig(config aws.Config, region string) (*AWSIoTTunneling, error) {
	client := iotsecuretunneling.NewFromConfig(config, func(options *iotsecuretunneling.Options) {
		options.Region = region
	})
	return NewAWSIoTTunneling(client, region)
}

// OpenTunnel calls iotsecuretunneling.OpenTunnel. AWS errors are wrapped via
// broker.TunnelingErrorClassifier so the pipeline can map
// LimitExceededException distinctly from generic AWS failures.
func (t *AWSIoTTunneling) OpenTunnel(ctx context.Context, request broker.TunnelOpenInternal) (broker.TunnelOpenResult, error) {
	output, err := t.client.OpenTunnel(ctx, &iotsecuretunneling.OpenTunnelInput{
		DestinationConfig: &types.DestinationConfig{
			ThingName: aws.String(request.ThingName),
			Services:  request.Services,
		},
		TimeoutConfig: &types.TimeoutConfig{
			MaxLifetimeTimeoutMinutes: aws.Int32(request.MaxLifetimeMinutes),
		},
	})
	if err != nil {
		return broker.TunnelOpenResult{}, classifyError(err)
	}

	if output.TunnelId == nil || *output.TunnelId == "" {
		return broker.TunnelOpenResult{}, wrap(broker.TunnelingErrorUnknown, errors.New("AWS IoT OpenTunnel returned empty tunnel id"))
	}
	if output.SourceAccessToken == nil || *output.SourceAccessToken == "" {
		return broker.TunnelOpenResult{}, wrap(broker.TunnelingErrorUnknown, errors.New("AWS IoT OpenTunnel returned empty source access token"))
	}

	return broker.TunnelOpenResult{
		TunnelID:          *output.TunnelId,
		SourceAccessToken: *output.SourceAccessToken,
		Region:            t.region,
	}, nil
}

// classifyError wraps AWS errors so the broker pipeline routes
// LimitExceededException → tunnel_limit_exceeded / 429 and everything else
// → tunneling_unavailable / 503 without importing the SDK error types.
func classifyError(err error) error {
	var limitExceeded *types.LimitExceededException
	if errors.As(err, &limitExceeded) {
		return wrap(broker.TunnelingErrorLimitExceeded, err)
	}
	return wrap(broker.TunnelingErrorUnknown, err)
}

// tunnelingError implements broker.TunnelingErrorClassifier; Unwrap keeps
// the inner SDK error reachable for errors.As / errors.Is callers.
type tunnelingError struct {
	kind broker.TunnelingErrorKind
	err  error
}

func wrap(kind broker.TunnelingErrorKind, err error) *tunnelingError {
	return &tunnelingError{kind: kind, err: err}
}

func (e *tunnelingError) Error() string {
	return fmt.Sprintf("tunneling: %v", e.err)
}

func (e *tunnelingError) Unwrap() error {
	return e.err
}

func (e *tunnelingError) TunnelingErrorKind() broker.TunnelingErrorKind {
	return e.kind
}
