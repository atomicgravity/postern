package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// emptyPayloadSHA256 is SHA-256 of the empty string, the payload-hash for
// GET requests with no body.
const emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

const awsExecuteAPIService = "execute-api"

// DefaultHTTPRegistryTimeout is the HTTP-Registry timeout when the caller
// doesn't inject its own *http.Client. 15s accommodates Lambda-cold-start
// latency typical of API-Gateway-fronted registries.
const DefaultHTTPRegistryTimeout = 15 * time.Second

// NewBearerAuthClient wraps inner so each request carries an Authorization:
// Bearer header. Token is sent verbatim — keep it in a secret store, not
// YAML.
func NewBearerAuthClient(inner HTTPClient, token string) HTTPClient {
	if inner == nil {
		inner = &http.Client{Timeout: DefaultHTTPRegistryTimeout}
	}
	return &bearerAuthClient{inner: inner, token: token}
}

type bearerAuthClient struct {
	inner HTTPClient
	token string
}

func (c *bearerAuthClient) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+c.token)
	return c.inner.Do(req)
}

// NewSigV4AuthClient wraps inner with AWS SigV4 signing against
// `execute-api` in region. Credentials come from provider — the broker
// resolves the SDK default chain at startup.
func NewSigV4AuthClient(inner HTTPClient, provider aws.CredentialsProvider, region string) HTTPClient {
	if inner == nil {
		inner = &http.Client{Timeout: DefaultHTTPRegistryTimeout}
	}
	return &sigV4AuthClient{
		inner:    inner,
		signer:   v4.NewSigner(),
		provider: provider,
		region:   region,
		now:      time.Now,
	}
}

type sigV4AuthClient struct {
	inner    HTTPClient
	signer   *v4.Signer
	provider aws.CredentialsProvider
	region   string
	now      func() time.Time
}

func (c *sigV4AuthClient) Do(req *http.Request) (*http.Response, error) {
	if c.provider == nil {
		return nil, errors.New("sigv4 auth: credentials provider is nil")
	}
	if strings.TrimSpace(c.region) == "" {
		return nil, errors.New("sigv4 auth: region is required")
	}
	creds, err := c.provider.Retrieve(req.Context())
	if err != nil {
		return nil, fmt.Errorf("sigv4 auth: retrieve credentials: %w", err)
	}
	if err := c.signer.SignHTTP(req.Context(), creds, req, emptyPayloadSHA256, awsExecuteAPIService, c.region, c.now()); err != nil {
		return nil, fmt.Errorf("sigv4 auth: sign request: %w", err)
	}
	return c.inner.Do(req)
}

// ErrHTTPURLRequired is returned when the registry HTTP URL is empty.
var ErrHTTPURLRequired = errors.New("registry HTTP URL is required")

// HTTPClient is the minimum surface HTTPRegistry consumes.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// HTTPRegistry issues GET ?device_id=... to an operator-provided endpoint
// and decodes the response.
type HTTPRegistry struct {
	client   HTTPClient
	endpoint url.URL
}

// HTTPRegistryResponse is the JSON shape the endpoint must return.
// Attribute values may be strings, booleans, or integer-valued JSON numbers;
// other shapes are dropped at the Policy boundary.
type HTTPRegistryResponse struct {
	Serial     string         `json:"serial"`
	FriendlyID string         `json:"friendly_id,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// NewHTTPRegistry constructs an HTTPRegistry with a default client capped by
// DefaultHTTPRegistryTimeout.
func NewHTTPRegistry(endpoint string) (*HTTPRegistry, error) {
	return NewHTTPRegistryWithClient(&http.Client{Timeout: DefaultHTTPRegistryTimeout}, endpoint)
}

// NewHTTPRegistryWithClient constructs an HTTPRegistry against a supplied
// client. nil falls back to the default.
func NewHTTPRegistryWithClient(client HTTPClient, endpoint string) (*HTTPRegistry, error) {
	if client == nil {
		client = &http.Client{Timeout: DefaultHTTPRegistryTimeout}
	}
	if endpoint == "" {
		return nil, ErrHTTPURLRequired
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse registry HTTP URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("registry HTTP URL must be an absolute http or https URL")
	}
	parsed.Fragment = ""
	return &HTTPRegistry{client: client, endpoint: *parsed}, nil
}

// ResolveDevice issues the lookup and decodes the response. 404 from the
// endpoint surfaces as 404; any other non-200 surfaces as 502 (registry-side
// problem, not caller input).
func (r *HTTPRegistry) ResolveDevice(ctx context.Context, deviceID string) (broker.DeviceRecord, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return broker.DeviceRecord{}, broker.Error{StatusCode: http.StatusBadRequest, Message: "device_id is required"}
	}

	endpoint := r.endpoint
	query := endpoint.Query()
	query.Set("device_id", deviceID)
	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return broker.DeviceRecord{}, fmt.Errorf("registry: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "postern-broker")

	response, err := r.client.Do(request)
	if err != nil {
		return broker.DeviceRecord{}, fmt.Errorf("query registry HTTP URL: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return broker.DeviceRecord{}, broker.Error{StatusCode: http.StatusNotFound, Message: "device not found"}
	}
	if response.StatusCode != http.StatusOK {
		return broker.DeviceRecord{}, broker.Error{StatusCode: http.StatusBadGateway, Message: "registry lookup failed"}
	}

	var lookup HTTPRegistryResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	if err := decoder.Decode(&lookup); err != nil {
		return broker.DeviceRecord{}, fmt.Errorf("decode registry response: %w", err)
	}
	return deviceRecordFromHTTPResponse(lookup)
}

func deviceRecordFromHTTPResponse(response HTTPRegistryResponse) (broker.DeviceRecord, error) {
	serial := strings.TrimSpace(response.Serial)
	if serial == "" {
		return broker.DeviceRecord{}, broker.Error{StatusCode: http.StatusBadGateway, Message: "registry response missing serial"}
	}
	if err := validateSerial(serial); err != nil {
		return broker.DeviceRecord{}, err
	}
	attributes := map[string]any{}
	for rawKey, rawValue := range response.Attributes {
		key := strings.TrimSpace(rawKey)
		if key == "" {
			continue
		}
		if normalized, ok := normalizeHTTPAttribute(rawValue); ok {
			attributes[key] = normalized
		}
	}
	return broker.DeviceRecord{
		Serial:     serial,
		FriendlyID: strings.TrimSpace(response.FriendlyID),
		Attributes: attributes,
	}, nil
}

// normalizeHTTPAttribute coerces a JSON-decoded value to one of (string,
// bool, int64). Whitespace-only strings drop; non-integer or out-of-range
// numerics drop; other types drop.
//
// The upper bound on the float→int64 check is `1<<63` because casting
// math.MaxInt64 to float64 rounds up to that exact value — comparing
// strictly less than it covers the overflow.
func normalizeHTTPAttribute(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return nil, false
		}
		return trimmed, true
	case bool:
		return typed, true
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil, false
		}
		if typed >= float64(1<<63) || typed < float64(math.MinInt64) {
			return nil, false
		}
		if math.Trunc(typed) != typed {
			return nil, false
		}
		return int64(typed), true
	default:
		return nil, false
	}
}
