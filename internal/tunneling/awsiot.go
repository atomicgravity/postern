// Package tunneling is the broker's Tunneling impl: AWS IoT Secure
// Tunneling, wrapping the SDK's OpenTunnel. The destination side receives
// its access token via AWS IoT MQTT directly — the broker is not in that
// data path.
package tunneling

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iotsecuretunneling"
	"github.com/aws/aws-sdk-go-v2/service/iotsecuretunneling/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
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

// DefaultRoleSessionName is the AssumeRole session name when the caller
// supplies none (outside Lambda, where the function name is unavailable).
const DefaultRoleSessionName = "postern-broker"

// maxRoleSessionNameLen is the STS RoleSessionName ceiling.
const maxRoleSessionNameLen = 64

// AWSIoTTunneling is the broker's Tunneling impl. Each OpenTunnel call
// translates broker.TunnelOpenInternal into one iotsecuretunneling RPC,
// either on the fixed client (own account + region) or, for a request with
// a Target, on a client holding that target role's assumed credentials.
type AWSIoTTunneling struct {
	client  AWSIoTClient
	region  string
	targets *targetClients
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

// NewAWSIoTTargetTunnelingFromConfig builds the registry-targeted impl: every
// request must carry a Target, and the tunnel opens in Target.Region with
// credentials from assuming Target.RoleARN. config supplies the broker's own
// credentials for the STS call. sessionName identifies the broker in the
// target account's CloudTrail; it is sanitized to the STS character set and
// length, and empty falls back to DefaultRoleSessionName.
func NewAWSIoTTargetTunnelingFromConfig(config aws.Config, sessionName string) *AWSIoTTunneling {
	stsClient := sts.NewFromConfig(config)
	sessionName = roleSessionName(sessionName)
	return newTargetTunneling(
		func(roleARN string) aws.CredentialsProvider {
			return aws.NewCredentialsCache(assumeRoleProvider{stscreds.NewAssumeRoleProvider(stsClient, roleARN, func(options *stscreds.AssumeRoleOptions) {
				options.RoleSessionName = sessionName
			})}, func(options *aws.CredentialsCacheOptions) {
				// Refresh early so a request never signs with credentials that expire in flight.
				options.ExpiryWindow = time.Minute
			})
		},
		func(credentials aws.CredentialsProvider, region string) AWSIoTClient {
			return iotsecuretunneling.NewFromConfig(config, func(options *iotsecuretunneling.Options) {
				options.Region = region
				options.Credentials = credentials
			})
		},
	)
}

func newTargetTunneling(newCredentials func(roleARN string) aws.CredentialsProvider, newClient func(aws.CredentialsProvider, string) AWSIoTClient) *AWSIoTTunneling {
	return &AWSIoTTunneling{targets: &targetClients{
		newCredentials: newCredentials,
		newClient:      newClient,
		credentials:    map[string]aws.CredentialsProvider{},
		clients:        map[broker.TunnelTarget]AWSIoTClient{},
	}}
}

// targetClients caches one credentials cache per role ARN (so concurrent
// requests share one AssumeRole until expiry) and one SDK client per
// (role, region). The key space is bounded by the broker's role allowlist
// times the regions devices name.
type targetClients struct {
	newCredentials func(roleARN string) aws.CredentialsProvider
	newClient      func(aws.CredentialsProvider, string) AWSIoTClient

	mu          sync.Mutex
	credentials map[string]aws.CredentialsProvider
	clients     map[broker.TunnelTarget]AWSIoTClient
}

func (c *targetClients) client(target broker.TunnelTarget) AWSIoTClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.clients[target]; ok {
		return client
	}
	credentials, ok := c.credentials[target.RoleARN]
	if !ok {
		credentials = c.newCredentials(target.RoleARN)
		c.credentials[target.RoleARN] = credentials
	}
	client := c.newClient(credentials, target.Region)
	c.clients[target] = client
	return client
}

// assumeRoleProvider tags AssumeRole failures so classifyError can tell
// them apart from OpenTunnel failures once the SDK has wrapped them.
type assumeRoleProvider struct {
	provider aws.CredentialsProvider
}

func (p assumeRoleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	credentials, err := p.provider.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, &assumeRoleError{err: err}
	}
	return credentials, nil
}

type assumeRoleError struct {
	err error
}

func (e *assumeRoleError) Error() string {
	return fmt.Sprintf("assume tunnel target role: %v", e.err)
}

func (e *assumeRoleError) Unwrap() error {
	return e.err
}

// roleSessionName maps name onto the STS RoleSessionName alphabet
// ([\w+=,.@-], 2-64 chars), replacing other characters with '-'.
func roleSessionName(name string) string {
	var builder strings.Builder
	for _, r := range strings.TrimSpace(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("_+=,.@-", r):
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	sanitized := builder.String()
	if len(sanitized) > maxRoleSessionNameLen {
		sanitized = sanitized[:maxRoleSessionNameLen]
	}
	if len(sanitized) < 2 {
		return DefaultRoleSessionName
	}
	return sanitized
}

// OpenTunnel calls iotsecuretunneling.OpenTunnel. AWS errors are wrapped via
// broker.TunnelingErrorClassifier so the pipeline can map
// LimitExceededException distinctly from generic AWS failures. A request
// whose Target presence doesn't match how the impl was built fails rather
// than opening the tunnel in the wrong account.
func (t *AWSIoTTunneling) OpenTunnel(ctx context.Context, request broker.TunnelOpenInternal) (broker.TunnelOpenResult, error) {
	client, region := t.client, t.region
	switch {
	case request.Target != nil && t.targets == nil:
		return broker.TunnelOpenResult{}, wrap(broker.TunnelingErrorUnknown, errors.New("tunnel target given but registry targeting is not configured"))
	case request.Target == nil && t.targets != nil:
		return broker.TunnelOpenResult{}, wrap(broker.TunnelingErrorUnknown, errors.New("registry targeting is configured but the request has no tunnel target"))
	case request.Target != nil:
		client, region = t.targets.client(*request.Target), request.Target.Region
	}

	output, err := client.OpenTunnel(ctx, &iotsecuretunneling.OpenTunnelInput{
		DestinationConfig: &types.DestinationConfig{
			ThingName: aws.String(request.ThingName),
			Services:  request.Services,
		},
		TimeoutConfig: &types.TimeoutConfig{
			MaxLifetimeTimeoutMinutes: aws.Int32(request.MaxLifetimeMinutes),
		},
	})
	if err != nil {
		return broker.TunnelOpenResult{}, classifyError(err, request.Target != nil)
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
		Region:            region,
	}, nil
}

// classifyError wraps AWS errors so the broker pipeline routes
// LimitExceededException → tunnel_limit_exceeded / 429, a registry target
// that refuses the broker → tunnel_target_access_denied / 500, and
// everything else → tunneling_unavailable / 503 without importing the SDK
// error types. Only access-denied codes count as a refusal: a throttled or
// failing STS stays retryable.
func classifyError(err error, targeted bool) error {
	var limitExceeded *types.LimitExceededException
	if errors.As(err, &limitExceeded) {
		return wrap(broker.TunnelingErrorLimitExceeded, err)
	}
	if targeted && accessDenied(err) {
		return wrap(broker.TunnelingErrorTargetAccessDenied, err)
	}
	return wrap(broker.TunnelingErrorUnknown, err)
}

// accessDenied reports an AssumeRole rejection (trust policy, disabled STS
// region) or an OpenTunnel AccessDeniedException in the target account.
func accessDenied(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	var assumeErr *assumeRoleError
	if errors.As(err, &assumeErr) {
		switch apiErr.ErrorCode() {
		case "AccessDenied", "RegionDisabledException":
			return true
		}
		return false
	}
	// The iotsecuretunneling model declares no AccessDeniedException type.
	return apiErr.ErrorCode() == "AccessDeniedException"
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
