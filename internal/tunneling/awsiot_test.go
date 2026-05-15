package tunneling

import (
	"context"
	"errors"
	"testing"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iotsecuretunneling"
	"github.com/aws/aws-sdk-go-v2/service/iotsecuretunneling/types"
)

// fakeIoTClient is the test-side recorder for the AWSIoTClient interface.
// Captures the per-call input so the test can assert OpenTunnel's request
// shape and returns a configurable output/error pair.
type fakeIoTClient struct {
	calls  []*iotsecuretunneling.OpenTunnelInput
	output *iotsecuretunneling.OpenTunnelOutput
	err    error
}

func (f *fakeIoTClient) OpenTunnel(_ context.Context, input *iotsecuretunneling.OpenTunnelInput, _ ...func(*iotsecuretunneling.Options)) (*iotsecuretunneling.OpenTunnelOutput, error) {
	f.calls = append(f.calls, input)
	if f.err != nil {
		return nil, f.err
	}
	return f.output, nil
}

func TestNewAWSIoTTunnelingRejectsEmptyRegion(t *testing.T) {
	_, err := NewAWSIoTTunneling(&fakeIoTClient{}, "")
	if !errors.Is(err, ErrTunnelingRegionRequired) {
		t.Fatalf("NewAWSIoTTunneling() error = %v, want ErrTunnelingRegionRequired", err)
	}
}

// TestOpenTunnelPassesRequestToSDK locks the SDK input wire: thing-name +
// services + max-lifetime flow through to iotsecuretunneling.OpenTunnel
// unchanged; the broker-side region pins the output's Region field.
func TestOpenTunnelPassesRequestToSDK(t *testing.T) {
	fake := &fakeIoTClient{
		output: &iotsecuretunneling.OpenTunnelOutput{
			TunnelId:          aws.String("tun-abc"),
			SourceAccessToken: aws.String("source-token"),
		},
	}
	tun, err := NewAWSIoTTunneling(fake, "us-west-2")
	if err != nil {
		t.Fatalf("NewAWSIoTTunneling() error = %v", err)
	}

	result, err := tun.OpenTunnel(context.Background(), broker.TunnelOpenInternal{
		ThingName:          "device-SERIAL123",
		Services:           []string{"SSH"},
		MaxLifetimeMinutes: 240,
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}

	if len(fake.calls) != 1 {
		t.Fatalf("SDK calls = %d, want 1", len(fake.calls))
	}
	input := fake.calls[0]
	if input.DestinationConfig == nil {
		t.Fatal("DestinationConfig missing")
	}
	if got, want := aws.ToString(input.DestinationConfig.ThingName), "device-SERIAL123"; got != want {
		t.Fatalf("ThingName = %q, want %q", got, want)
	}
	if got, want := input.DestinationConfig.Services, []string{"SSH"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("Services = %v, want %v", got, want)
	}
	if input.TimeoutConfig == nil {
		t.Fatal("TimeoutConfig missing")
	}
	if got, want := aws.ToInt32(input.TimeoutConfig.MaxLifetimeTimeoutMinutes), int32(240); got != want {
		t.Fatalf("MaxLifetimeTimeoutMinutes = %d, want %d", got, want)
	}

	if got, want := result.TunnelID, "tun-abc"; got != want {
		t.Fatalf("TunnelID = %q, want %q", got, want)
	}
	if got, want := result.SourceAccessToken, "source-token"; got != want {
		t.Fatalf("SourceAccessToken = %q, want %q", got, want)
	}
	if got, want := result.Region, "us-west-2"; got != want {
		t.Fatalf("Region = %q, want %q", got, want)
	}
}

// TestOpenTunnelMapsLimitExceededToClassifier locks the AWS-error → broker-
// classifier wrapping: a LimitExceededException emerges from OpenTunnel as
// an error implementing TunnelingErrorClassifier with kind
// TunnelingErrorLimitExceeded. The broker pipeline uses the classifier to
// route to denied_reason: tunnel_limit_exceeded.
func TestOpenTunnelMapsLimitExceededToClassifier(t *testing.T) {
	fake := &fakeIoTClient{err: &types.LimitExceededException{Message: aws.String("over quota")}}
	tun, err := NewAWSIoTTunneling(fake, "us-west-2")
	if err != nil {
		t.Fatalf("NewAWSIoTTunneling() error = %v", err)
	}

	_, err = tun.OpenTunnel(context.Background(), broker.TunnelOpenInternal{
		ThingName:          "device-SERIAL123",
		Services:           []string{"SSH"},
		MaxLifetimeMinutes: 240,
	})
	if err == nil {
		t.Fatal("OpenTunnel() returned nil error")
	}
	classifier, ok := err.(broker.TunnelingErrorClassifier)
	if !ok {
		t.Fatalf("error type = %T, does not implement TunnelingErrorClassifier", err)
	}
	if got, want := classifier.TunnelingErrorKind(), broker.TunnelingErrorLimitExceeded; got != want {
		t.Fatalf("kind = %d, want %d (TunnelingErrorLimitExceeded)", got, want)
	}
}

// TestOpenTunnelWrapsGenericErrorsAsUnknown locks the default error
// classification: an AWS error type the impl doesn't recognize wraps
// to TunnelingErrorUnknown so the broker pipeline routes it to
// tunneling_unavailable.
func TestOpenTunnelWrapsGenericErrorsAsUnknown(t *testing.T) {
	fake := &fakeIoTClient{err: errors.New("network unreachable")}
	tun, err := NewAWSIoTTunneling(fake, "us-west-2")
	if err != nil {
		t.Fatalf("NewAWSIoTTunneling() error = %v", err)
	}

	_, err = tun.OpenTunnel(context.Background(), broker.TunnelOpenInternal{
		ThingName: "device-SERIAL123",
		Services:  []string{"SSH"},
	})
	if err == nil {
		t.Fatal("OpenTunnel() returned nil error")
	}
	classifier, ok := err.(broker.TunnelingErrorClassifier)
	if !ok {
		t.Fatalf("error type = %T, does not implement TunnelingErrorClassifier", err)
	}
	if got, want := classifier.TunnelingErrorKind(), broker.TunnelingErrorUnknown; got != want {
		t.Fatalf("kind = %d, want %d (TunnelingErrorUnknown)", got, want)
	}
}

// TestOpenTunnelRejectsEmptySDKResponse locks the defensive guard against
// an SDK output with missing tunnel-id or source-access-token. AWS docs
// say these are always populated on a successful OpenTunnel; an empty
// value is a wrapped non-classifier error mapping to tunneling_unavailable.
func TestOpenTunnelRejectsEmptySDKResponse(t *testing.T) {
	cases := []struct {
		name   string
		output *iotsecuretunneling.OpenTunnelOutput
	}{
		{
			"empty tunnel id",
			&iotsecuretunneling.OpenTunnelOutput{SourceAccessToken: aws.String("token")},
		},
		{
			"empty source access token",
			&iotsecuretunneling.OpenTunnelOutput{TunnelId: aws.String("tun-abc")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeIoTClient{output: tc.output}
			tun, err := NewAWSIoTTunneling(fake, "us-west-2")
			if err != nil {
				t.Fatalf("NewAWSIoTTunneling() error = %v", err)
			}
			_, err = tun.OpenTunnel(context.Background(), broker.TunnelOpenInternal{
				ThingName: "device-SERIAL123",
				Services:  []string{"SSH"},
			})
			if err == nil {
				t.Fatal("OpenTunnel() returned nil error on empty SDK response")
			}
			classifier, ok := err.(broker.TunnelingErrorClassifier)
			if !ok {
				t.Fatalf("error type = %T, does not implement TunnelingErrorClassifier", err)
			}
			if got, want := classifier.TunnelingErrorKind(), broker.TunnelingErrorUnknown; got != want {
				t.Fatalf("kind = %d, want %d (empty-response should map to Unknown)", got, want)
			}
		})
	}
}
