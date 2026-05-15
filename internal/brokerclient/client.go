// Package brokerclient is the CLI-side HTTP client for the broker. It issues
// authenticated POSTs against the broker endpoints and decodes responses
// into the broker.* domain types.
package brokerclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/atomicgravity/postern/internal/broker"
)

// defaultHTTPTimeout bounds each broker call. Applied via context.WithTimeout
// so it composes with the engineer's signal-cancel context.
const defaultHTTPTimeout = 30 * time.Second

// Client is the CLI-side broker HTTP client. Safe to reuse.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// New constructs a Client pointed at baseURL; nil httpClient falls back to
// http.DefaultClient.
func New(baseURL string, httpClient *http.Client) Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return Client{baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"), httpClient: httpClient}
}

// postJSON is the shared transport for every broker POST. label is the
// engineer-facing verb flowing into error wraps.
func postJSON[Resp any](ctx context.Context, c Client, accessToken, endpointPath, label string, requestBody any) (Resp, error) {
	var zero Resp

	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return zero, errors.New("access token is required")
	}

	endpoint, err := c.endpoint(endpointPath)
	if err != nil {
		return zero, err
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return zero, err
	}

	requestCtx, cancel := context.WithTimeout(ctx, defaultHTTPTimeout)
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return zero, err
	}
	httpRequest.Header.Set("Authorization", "Bearer "+accessToken)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")

	response, err := c.httpClient.Do(httpRequest)
	if err != nil {
		return zero, fmt.Errorf("%s: %w", label, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return zero, fmt.Errorf("%s: status %s: %s", label, response.Status, strings.TrimSpace(string(responseBody)))
	}

	var decoded Resp
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		return zero, fmt.Errorf("decode %s response: %w", label, err)
	}

	return decoded, nil
}

// RequestTimePayload posts /ssh/time-payload and returns the JWS Compact
// string the engineer pipes to the device's verifier. Client-side validation
// is non-emptiness only; the broker is the contract authority.
func (c Client) RequestTimePayload(ctx context.Context, accessToken, deviceID, nonce string) (string, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return "", errors.New("device id is required")
	}
	nonce = strings.TrimSpace(nonce)
	if nonce == "" {
		return "", errors.New("nonce is required")
	}

	timePayloadResponse, err := postJSON[broker.TimePayloadIssueResponse](ctx, c, accessToken, "/ssh/time-payload", "request time payload", broker.TimePayloadIssueRequest{
		DeviceID: deviceID,
		Nonce:    nonce,
	})
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(timePayloadResponse.TimePayload) == "" {
		return "", errors.New("time payload response missing time_payload")
	}

	return timePayloadResponse.TimePayload, nil
}

// MintSSHCert posts /ssh/cert. Client-side validation is non-emptiness only;
// PrincipalType and other wire-shape constraints are the broker's contract.
func (c Client) MintSSHCert(ctx context.Context, accessToken string, request broker.SSHCertIssueRequest) (broker.SSHCertIssueResponse, error) {
	request.DeviceID = strings.TrimSpace(request.DeviceID)
	if request.DeviceID == "" {
		return broker.SSHCertIssueResponse{}, errors.New("device id is required")
	}
	if request.PrincipalType == "" {
		return broker.SSHCertIssueResponse{}, errors.New("principal type is required")
	}
	request.PublicKey = strings.TrimSpace(request.PublicKey)
	if request.PublicKey == "" {
		return broker.SSHCertIssueResponse{}, errors.New("public key is required")
	}

	certResponse, err := postJSON[broker.SSHCertIssueResponse](ctx, c, accessToken, "/ssh/cert", "mint SSH cert", request)
	if err != nil {
		return broker.SSHCertIssueResponse{}, err
	}

	if strings.TrimSpace(certResponse.SSHCert) == "" {
		return broker.SSHCertIssueResponse{}, errors.New("SSH cert response missing ssh_cert")
	}

	return certResponse, nil
}

// OpenTunnel posts /ssh/tunnel and returns the source access token + tunnel
// ID + region the CLI's source proxy dials. maxLifetimeMinutes=0 means use
// the broker's default; the broker clamps by the AWS 12h ceiling and Cedar
// policy and returns the resolved TTL.
func (c Client) OpenTunnel(ctx context.Context, accessToken, deviceID string, maxLifetimeMinutes int32) (broker.TunnelOpenResponse, error) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return broker.TunnelOpenResponse{}, errors.New("device id is required")
	}
	if maxLifetimeMinutes < 0 {
		return broker.TunnelOpenResponse{}, errors.New("max lifetime minutes must be non-negative")
	}

	tunnelResponse, err := postJSON[broker.TunnelOpenResponse](ctx, c, accessToken, "/ssh/tunnel", "open tunnel", broker.TunnelOpenRequest{
		DeviceID:           deviceID,
		MaxLifetimeMinutes: maxLifetimeMinutes,
	})
	if err != nil {
		return broker.TunnelOpenResponse{}, err
	}

	if strings.TrimSpace(tunnelResponse.SourceAccessToken) == "" {
		return broker.TunnelOpenResponse{}, errors.New("tunnel response missing source_access_token")
	}
	if strings.TrimSpace(tunnelResponse.TunnelID) == "" {
		return broker.TunnelOpenResponse{}, errors.New("tunnel response missing tunnel_id")
	}
	if strings.TrimSpace(tunnelResponse.Region) == "" {
		return broker.TunnelOpenResponse{}, errors.New("tunnel response missing region")
	}

	return tunnelResponse, nil
}

func (c Client) endpoint(endpointPath string) (string, error) {
	if c.baseURL == "" {
		return "", errors.New("broker URL is required")
	}

	parsed, err := url.Parse(c.baseURL)
	if err != nil {
		return "", fmt.Errorf("parse broker URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("broker URL must be absolute")
	}

	// Reject http:// except for loopback. The CLI sends the bearer access
	// token over this connection; plaintext exposes it to anyone on path.
	if parsed.Scheme != "https" {
		host := parsed.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", fmt.Errorf("broker URL must use https (got %q); use a TLS-fronted broker or http://localhost for local development", parsed.Scheme)
		}
	}

	parsed.Path = strings.TrimRight(parsed.Path, "/") + endpointPath
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return parsed.String(), nil
}
