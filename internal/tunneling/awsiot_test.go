package tunneling

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iotsecuretunneling"
	"github.com/aws/aws-sdk-go-v2/service/iotsecuretunneling/types"
	"github.com/aws/smithy-go"
)

// fakeIoTClient is the test-side recorder for the AWSIoTClient interface.
// Captures the per-call input so the test can assert OpenTunnel's request
// shape and returns a configurable output/error pair.
type fakeIoTClient struct {
	mu     sync.Mutex
	calls  []*iotsecuretunneling.OpenTunnelInput
	output *iotsecuretunneling.OpenTunnelOutput
	err    error
}

func (f *fakeIoTClient) OpenTunnel(_ context.Context, input *iotsecuretunneling.OpenTunnelInput, _ ...func(*iotsecuretunneling.Options)) (*iotsecuretunneling.OpenTunnelOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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

// failingCredentials stands in for an AssumeRole provider whose STS call fails.
type failingCredentials struct{ err error }

func (f failingCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{}, f.err
}

// TestOpenTunnelTargetAccessDeniedClassification locks which failures count
// as a target-account refusal. The AssumeRole cases run through a real SDK
// client, so the classification must survive the SDK's own wrapping of a
// credentials error; they fail before any request is sent.
func TestOpenTunnelTargetAccessDeniedClassification(t *testing.T) {
	target := &broker.TunnelTarget{RoleARN: "arn:aws:iam::111122223333:role/tunnel", Region: "eu-central-1"}
	sdkClient := func(stsErr error) *AWSIoTTunneling {
		return newTargetTunneling(
			func(string) aws.CredentialsProvider {
				return aws.NewCredentialsCache(assumeRoleProvider{failingCredentials{err: stsErr}})
			},
			func(credentials aws.CredentialsProvider, region string) AWSIoTClient {
				return iotsecuretunneling.New(iotsecuretunneling.Options{Region: region, Credentials: credentials, RetryMaxAttempts: 1})
			},
		)
	}
	fakeClient := func(err error) *AWSIoTTunneling {
		return newTargetTunneling(
			func(string) aws.CredentialsProvider { return &staticCredentials{} },
			func(aws.CredentialsProvider, string) AWSIoTClient { return &fakeIoTClient{err: err} },
		)
	}
	openDenied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}
	fixed, err := NewAWSIoTTunneling(&fakeIoTClient{err: openDenied}, "us-west-2")
	if err != nil {
		t.Fatalf("NewAWSIoTTunneling() error = %v", err)
	}

	cases := []struct {
		name   string
		tun    *AWSIoTTunneling
		target *broker.TunnelTarget
		want   broker.TunnelingErrorKind
	}{
		{"assume role denied", sdkClient(&smithy.GenericAPIError{Code: "AccessDenied"}), target, broker.TunnelingErrorTargetAccessDenied},
		{"STS region disabled", sdkClient(&smithy.GenericAPIError{Code: "RegionDisabledException"}), target, broker.TunnelingErrorTargetAccessDenied},
		{"assume role throttled stays retryable", sdkClient(&smithy.GenericAPIError{Code: "Throttling"}), target, broker.TunnelingErrorUnknown},
		{"assume role network failure stays retryable", sdkClient(errors.New("dial tcp: timeout")), target, broker.TunnelingErrorUnknown},
		{"open tunnel denied in target account", fakeClient(openDenied), target, broker.TunnelingErrorTargetAccessDenied},
		{"open tunnel denied in own account", fixed, nil, broker.TunnelingErrorUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.tun.OpenTunnel(context.Background(), broker.TunnelOpenInternal{
				ThingName:          "device-SERIAL123",
				Services:           []string{"SSH"},
				MaxLifetimeMinutes: 60,
				Target:             tc.target,
			})
			var classifier broker.TunnelingErrorClassifier
			if !errors.As(err, &classifier) {
				t.Fatalf("OpenTunnel() error = %v, want a TunnelingErrorClassifier", err)
			}
			if got := classifier.TunnelingErrorKind(); got != tc.want {
				t.Fatalf("kind = %d, want %d (err = %v)", got, tc.want, err)
			}
		})
	}
}

// staticCredentials is a distinguishable CredentialsProvider for cache tests.
type staticCredentials struct{ roleARN string }

func (s *staticCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: s.roleARN}, nil
}

type targetFactoryRecorder struct {
	mu              sync.Mutex
	credentialCalls map[string]int
	clientCalls     map[broker.TunnelTarget]int
	clients         map[broker.TunnelTarget]*fakeIoTClient
}

func newTargetFactoryRecorder() *targetFactoryRecorder {
	return &targetFactoryRecorder{
		credentialCalls: map[string]int{},
		clientCalls:     map[broker.TunnelTarget]int{},
		clients:         map[broker.TunnelTarget]*fakeIoTClient{},
	}
}

func (r *targetFactoryRecorder) tunneling(t *testing.T) *AWSIoTTunneling {
	t.Helper()
	return newTargetTunneling(
		func(roleARN string) aws.CredentialsProvider {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.credentialCalls[roleARN]++
			return &staticCredentials{roleARN: roleARN}
		},
		func(credentials aws.CredentialsProvider, region string) AWSIoTClient {
			r.mu.Lock()
			defer r.mu.Unlock()
			roleARN := credentials.(*staticCredentials).roleARN
			target := broker.TunnelTarget{RoleARN: roleARN, Region: region}
			r.clientCalls[target]++
			client := &fakeIoTClient{output: &iotsecuretunneling.OpenTunnelOutput{
				TunnelId:          aws.String("tun-" + region),
				SourceAccessToken: aws.String("source-token"),
			}}
			r.clients[target] = client
			return client
		},
	)
}

// TestOpenTunnelTargetUsesTargetClientAndRegion locks on-mode: the call goes
// to the client built for the request's (role, region) and the result's
// Region is the target region.
func TestOpenTunnelTargetUsesTargetClientAndRegion(t *testing.T) {
	recorder := newTargetFactoryRecorder()
	tun := recorder.tunneling(t)
	target := broker.TunnelTarget{RoleARN: "arn:aws:iam::111122223333:role/tunnel", Region: "eu-central-1"}

	result, err := tun.OpenTunnel(context.Background(), broker.TunnelOpenInternal{
		ThingName:          "device-SERIAL123",
		Services:           []string{"SSH"},
		MaxLifetimeMinutes: 60,
		Target:             &target,
	})
	if err != nil {
		t.Fatalf("OpenTunnel() error = %v", err)
	}
	if got, want := result.Region, "eu-central-1"; got != want {
		t.Fatalf("Region = %q, want %q", got, want)
	}
	if got, want := result.TunnelID, "tun-eu-central-1"; got != want {
		t.Fatalf("TunnelID = %q, want %q", got, want)
	}
	if got := len(recorder.clients[target].calls); got != 1 {
		t.Fatalf("target client calls = %d, want 1", got)
	}
}

// TestOpenTunnelTargetCachesCredentialsAndClients locks the cache shape: one
// credentials provider per role, one client per (role, region), reused
// across calls including concurrent ones.
func TestOpenTunnelTargetCachesCredentialsAndClients(t *testing.T) {
	recorder := newTargetFactoryRecorder()
	tun := recorder.tunneling(t)
	roleA := "arn:aws:iam::111122223333:role/tunnel"
	roleB := "arn:aws:iam::444455556666:role/tunnel"
	targets := []broker.TunnelTarget{
		{RoleARN: roleA, Region: "us-east-1"},
		{RoleARN: roleA, Region: "us-east-1"},
		{RoleARN: roleA, Region: "eu-central-1"},
		{RoleARN: roleB, Region: "us-east-1"},
	}

	var wg sync.WaitGroup
	for round := 0; round < 8; round++ {
		for _, target := range targets {
			wg.Add(1)
			go func(target broker.TunnelTarget) {
				defer wg.Done()
				if _, err := tun.OpenTunnel(context.Background(), broker.TunnelOpenInternal{ThingName: "device-X", Target: &target}); err != nil {
					t.Errorf("OpenTunnel(%+v) error = %v", target, err)
				}
			}(target)
		}
	}
	wg.Wait()

	if got, want := recorder.credentialCalls, map[string]int{roleA: 1, roleB: 1}; len(got) != len(want) || got[roleA] != 1 || got[roleB] != 1 {
		t.Fatalf("credential constructions = %v, want %v", got, want)
	}
	if got := len(recorder.clientCalls); got != 3 {
		t.Fatalf("distinct clients = %d, want 3", got)
	}
	for target, count := range recorder.clientCalls {
		if count != 1 {
			t.Fatalf("client for %+v constructed %d times, want 1", target, count)
		}
	}
}

// TestOpenTunnelTargetModeMismatch locks fail-closed behavior: a target on a
// fixed-account impl, or no target on a registry-targeted impl, never opens
// a tunnel.
func TestOpenTunnelTargetModeMismatch(t *testing.T) {
	fixedClient := &fakeIoTClient{}
	fixed, err := NewAWSIoTTunneling(fixedClient, "us-west-2")
	if err != nil {
		t.Fatalf("NewAWSIoTTunneling() error = %v", err)
	}
	target := broker.TunnelTarget{RoleARN: "arn:aws:iam::111122223333:role/tunnel", Region: "us-east-1"}
	if _, err := fixed.OpenTunnel(context.Background(), broker.TunnelOpenInternal{ThingName: "device-X", Target: &target}); err == nil {
		t.Fatal("fixed impl with target: error = nil, want failure")
	}
	if len(fixedClient.calls) != 0 {
		t.Fatalf("fixed client calls = %d, want 0", len(fixedClient.calls))
	}

	recorder := newTargetFactoryRecorder()
	targeted := recorder.tunneling(t)
	if _, err := targeted.OpenTunnel(context.Background(), broker.TunnelOpenInternal{ThingName: "device-X"}); err == nil {
		t.Fatal("targeted impl without target: error = nil, want failure")
	}
	if len(recorder.clientCalls) != 0 {
		t.Fatalf("target clients built = %d, want 0", len(recorder.clientCalls))
	}
}

// TestNewAWSIoTTargetTunnelingFromConfigBuildsClients exercises the
// production factories offline: credentials are a CredentialsCache and
// clients are cached per target, with no AWS call until OpenTunnel runs.
func TestNewAWSIoTTargetTunnelingFromConfigBuildsClients(t *testing.T) {
	tun := NewAWSIoTTargetTunnelingFromConfig(aws.Config{Region: "us-east-1"}, "my-broker")
	target := broker.TunnelTarget{RoleARN: "arn:aws:iam::111122223333:role/tunnel", Region: "eu-central-1"}
	first := tun.targets.client(target)
	if second := tun.targets.client(target); first != second {
		t.Fatal("client not reused for the same target")
	}
	if _, ok := tun.targets.credentials[target.RoleARN].(*aws.CredentialsCache); !ok {
		t.Fatalf("credentials = %T, want *aws.CredentialsCache", tun.targets.credentials[target.RoleARN])
	}
}

func TestRoleSessionName(t *testing.T) {
	long := strings.Repeat("a", 80)
	cases := map[string]string{
		"":                      DefaultRoleSessionName,
		"x":                     DefaultRoleSessionName,
		"postern-common-broker": "postern-common-broker",
		"has space/and:colon":   "has-space-and-colon",
		long:                    long[:64],
	}
	for input, want := range cases {
		if got := roleSessionName(input); got != want {
			t.Errorf("roleSessionName(%q) = %q, want %q", input, got, want)
		}
	}
}
